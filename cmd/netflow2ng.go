package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	localformatters "github.com/synfinatic/netflow2ng/formatter"
	localtransport "github.com/synfinatic/netflow2ng/transport"
	"gopkg.in/yaml.v3"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/format"
	_ "github.com/netsampler/goflow2/v2/format/json"
	"github.com/netsampler/goflow2/v2/metrics"
	"github.com/netsampler/goflow2/v2/producer"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/transport"
	_ "github.com/netsampler/goflow2/v2/transport/file"
	"github.com/netsampler/goflow2/v2/utils"
	"github.com/netsampler/goflow2/v2/utils/debug"
)

var (
	COPYRIGHT_YEAR string = "2020-2022"
	Version        string = "unknown"
	Buildinfos     string = "unknown"
	Delta          string = ""
	CommitID       string = "unknown"
	Tag            string = "NO-TAG"
	log            *logrus.Logger
	rctx           RunContext
)

type RunContext struct {
	Kctx *kong.Context
	cli  CLI
}

type SourceId int

func (s *SourceId) Validate() error {
	if *s < 0 || *s > 255 {
		return fmt.Errorf("must be betweeen 0 and 255")
	}
	return nil
}

type Address string

func (a *Address) Value() (string, int) {
	var port int64
	var err error

	listen := strings.SplitN(string(*a), ":", 2)
	if port, err = strconv.ParseInt(listen[1], 10, 16); err != nil {
		log.Fatalf("Unable to parse: --listen %s", string(*a))
	}
	return listen[0], int(port)
}

type CLI struct {
	ListenNf Address `kong:"short='a',help='NetFlow/IPFIX listen address:port',default='0.0.0.0:2055'"`
	Reuse    bool    `kong:"help='Enable SO_REUSEPORT for NetFlow/IPFIX listen port'"`

	Metrics Address `kong:"short='m',help='Metrics listen address',default='0.0.0.0:8080'"`

	ListenZmq string   `kong:"short='z',help='proto://IP:Port to listen on for ZMQ connections',default='tcp://*:5556'"`
	Topic     string   `kong:"help='ZMQ Topic',default='flow'"`
	SourceId  SourceId `kong:"help='NetFlow SourceId (0-255)',default=0"`
	Compress  bool     `kong:"help='Compress ZMQ JSON data',xor='zmq-data'"`
	Protobuf  bool     `kong:"help='Use ProtoBuff instead of JSQN for ZMQ',xor='zmq-data'"`
	TLV       bool     `kong:"help='Use TLV instead of JSQN for ZMQ (needed for ntopng 6.4 and later)',xor='zmq-data'"`

	Workers   int    `kong:"short='w',help='Number of NetFlow workers',default=1"`
	LogLevel  string `kong:"short='l',help='Log level [error|warn|info|debug|trace]',default='info',enum='error,warn,info,debug,trace'"`
	LogFormat string `kong:"short='f',help='Log format [default|json]',default='default',enum='default,json'"`
	Version   bool   `kong:"short='v',help='Print version and copyright info'"`
}

// goflow supported serving up the NFv9 templates via http. Goflow2 doesn't.
// TODO: Add an http endpoint that grabs the NFv9 templates from goflow2/decoders/netflow/templates.go
//
//	and serves up a plain text list that go go our over http.
/*func httpServer(metricsAddress string) {
	http.Handle("/metrics", promhttp.Handler())
	//http.HandleFunc("/templates", state.ServeHTTPTemplates)
	log.Fatal(http.ListenAndServe(metricsAddress, nil))
}*/

// FreeBSD/pfSense/OPNsense has a bug where OUT_BYTES are included, but always 0. We need to
// map OUT_BYTES to some other field, so goflow processing doesn't overwrite IN_BYTES with this
// zeros.

func LoadMappingYaml() (*protoproducer.ProducerConfig, error) {
	config := &protoproducer.ProducerConfig{}
	dec := yaml.NewDecoder(strings.NewReader(localformatters.MappingYamlStr))
	err := dec.Decode(config)
	return config, err
}

func main() {
	var err error
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       true,
	})

	parser := kong.Must(
		&rctx.cli,
		kong.Name("netflow2ng"),
		kong.Description("NetFlow v9/IPFIX Proxy for ntopng"),
		kong.UsageOnError(),
	)

	rctx.Kctx, err = parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	if rctx.cli.Version {
		PrintVersion()
		os.Exit(0)
	}

	lvl, _ := logrus.ParseLevel(rctx.cli.LogLevel)
	log.SetLevel(lvl)
	localformatters.SetLogger(log)
	localtransport.SetLogger(log)

	var msgType localtransport.MsgFormat
	var formatter *format.Format

	if rctx.cli.Protobuf {
		msgType = localtransport.PBUF
		log.Fatal("Protobuf not yet supported with goflow2")
	} else if rctx.cli.TLV {
		msgType = localtransport.TLV
		formatter, err = format.FindFormat("ntoptlv")
		log.Info("Using ntopng TLV format for ZMQ")
	} else {
		msgType = localtransport.JSON
		formatter, err = format.FindFormat("ntopjson")
		log.Info("Using ntopng JSON format for ZMQ")
	}

	if err != nil {
		log.Error("Avail formatters:", format.GetFormats())
		log.Fatal("error formatter", err)
	}

	localtransport.RegisterZmq(rctx.cli.ListenZmq, msgType, int(rctx.cli.SourceId), rctx.cli.Compress)

	transporter, err := transport.FindTransport("zmq")
	if err != nil {
		log.Error("Avail transporters:", transport.GetTransports())
		log.Fatal("error transporter", err)
	}

	var flowProducer producer.ProducerInterface
	// instanciate a producer
	// unlike transport and format, the producer requires extensive configurations and can be chained

	// We use our own mapping config to keep goflow2 from overwriting IN_BYTES with 0 from OUT_BYTES
	cfgProducer, err := LoadMappingYaml()
	if err != nil {
		slog.Error("error loading mapping", slog.String("error", err.Error()))
		os.Exit(1)
	}

	cfgm, err := cfgProducer.Compile() // converts configuration into a format that can be used by a protobuf producer
	if err != nil {
		log.Fatal(err)
	}

	flowProducer, err = protoproducer.CreateProtoProducer(cfgm, protoproducer.CreateSamplingSystem)
	if err != nil {
		log.Fatal("error producer", err)
	}

	// intercept panic and generate an error
	flowProducer = debug.WrapPanicProducer(flowProducer)
	// wrap producer with Prometheus metrics
	flowProducer = metrics.WrapPromProducer(flowProducer)

	wg := &sync.WaitGroup{}

	var collecting bool
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/__health", func(wr http.ResponseWriter, r *http.Request) {
		if !collecting {
			wr.WriteHeader(http.StatusServiceUnavailable)
			if _, err := wr.Write([]byte("Not OK\n")); err != nil {
				slog.Error("error writing HTTP", slog.String("error", err.Error()))
			}
		} else {
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write([]byte("OK\n")); err != nil {
				slog.Error("error writing HTTP", slog.String("error", err.Error()))

			}
		}
	})
	srv := http.Server{
		Addr:              string(rctx.cli.Metrics),
		ReadHeaderTimeout: time.Second * 5,
	}
	if srv.Addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := srv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("HTTP server error", slog.String("error", err.Error()))
				os.Exit(1)
			}
			slog.Info("closed HTTP server")
		}()
	}

	slog.Info("starting GoFlow2")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	var receivers []*utils.UDPReceiver
	var pipes []utils.FlowPipe

	q := make(chan bool)

	Nfv9Ip, Nfv9Port := rctx.cli.ListenNf.Value()

	// TODOL Sort of sockets, works, queue, and blocking
	numSockets := 1

	numWorkers := numSockets * 2

	queueSize := 1000000

	log.Info("starting collection")

	cfg := &utils.UDPReceiverConfig{
		Sockets:          numSockets,
		Workers:          numWorkers,
		QueueSize:        queueSize,
		Blocking:         false,
		ReceiverCallback: metrics.NewReceiverMetric(),
	}
	recv, err := utils.NewUDPReceiver(cfg)
	if err != nil {
		log.Error("error creating UDP receiver", slog.String("error", err.Error()))
		os.Exit(1)
	}

	cfgPipe := &utils.PipeConfig{
		Format:           formatter,
		Transport:        transporter,
		Producer:         flowProducer,
		NetFlowTemplater: metrics.NewDefaultPromTemplateSystem, // wrap template system to get Prometheus info
	}

	var decodeFunc utils.DecoderFunc
	p := utils.NewNetFlowPipe(cfgPipe)

	decodeFunc = p.DecodeFlow
	// intercept panic and generate error
	decodeFunc = debug.PanicDecoderWrapper(decodeFunc)
	// wrap decoder with Prometheus metrics
	decodeFunc = metrics.PromDecoderWrapper(decodeFunc, "netflow")
	pipes = append(pipes, p)

	// starts receivers
	// the function either returns an error
	if err := recv.Start(Nfv9Ip, Nfv9Port, decodeFunc); err != nil {
		log.Fatal("error starting netflow reciever: ", Nfv9Ip, Nfv9Port)
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-q:
					return
				case err := <-recv.Errors():
					if errors.Is(err, net.ErrClosed) {
						log.Info("closed receiver")
						continue
					} else if !errors.Is(err, netflow.ErrorTemplateNotFound) && !errors.Is(err, debug.PanicError) {
						log.Error("error", err)
						continue
					} else {
						if errors.Is(err, netflow.ErrorTemplateNotFound) {
							log.Info("template error: ", err)
						} else if errors.Is(err, debug.PanicError) {
							var pErrMsg *debug.PanicErrorMessage
							log.Error("intercepted panic", pErrMsg)
						} else {
							log.Error(err)
						}
					}
				}
			}
		}()
		receivers = append(receivers, recv)
	}

	collecting = true

	<-c

	collecting = false

	// stops receivers first, udp sockets will be down
	for _, recv := range receivers {
		if err := recv.Stop(); err != nil {
			log.Error("error stopping receiver", err)
		}
	}
	// then stop pipe
	for _, pipe := range pipes {
		pipe.Close()
	}
	// close producer
	flowProducer.Close()
	// close transporter (eg: flushes message to Kafka)
	transporter.Close()
	log.Info("transporter closed")
	// close http server (prometheus + health check)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("error shutting-down HTTP server", err)
	}
	cancel()
	close(q) // close errors
	wg.Wait()

	/*
		var defaultTransport utils.Transport
		defaultTransport = &utils.DefaultLogTransport{}

		switch rctx.cli.LogFormat {
		case "json":
			log.SetFormatter(&logrus.JSONFormatter{})
			defaultTransport = &utils.DefaultJSONTransport{}
		case "default":
			log.Debugf("Using default log style")
		}

		runtime.GOMAXPROCS(runtime.NumCPU())

		log.Info("Starting netflow2ng")

		s := &utils.StateNetFlow{
			Transport: defaultTransport,
			Logger:    log,
		}

		go httpServer(s, string(rctx.cli.Metrics))

		if s.Transport, err = StartZmqProducer(); err != nil {
			log.Fatal(err)
		}

		ip, port := rctx.cli.Listen.Value()

		log.WithFields(logrus.Fields{
			"Type": "NetFlow"}).
			Infof("Listening on UDP %s", rctx.cli.Listen)

		if err = s.FlowRoutine(rctx.cli.Workers, ip, port, rctx.cli.Reuse); err != nil {
			log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
		}
	*/

}

func PrintVersion() {
	delta := ""
	if len(Delta) > 0 {
		delta = fmt.Sprintf(" [%s delta]", Delta)
		Tag = "Unknown"
	}
	fmt.Printf("netflow2ng v%s -- Copyright %s Aaron Turner\n", Version, COPYRIGHT_YEAR)
	fmt.Printf("%s (%s)%s built at %s\n", CommitID, Tag, delta, Buildinfos)
}
