package main

import (
	"context"
	"errors"
	"fmt"
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
		return fmt.Errorf("must be between 0 and 255")
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
	Listen Address `short:"a" help:"NetFlow/IPFIX listen address:port" default:"0.0.0.0:2055"`
	Reuse  bool    `help:"Enable SO_REUSEPORT for NetFlow/IPFIX listen port"`

	Metrics Address `short:"m" help:"Metrics listen address" default:"0.0.0.0:8080"`

	ListenZmq string   `short:"z" help:"proto://IP:Port to listen on for ZMQ connections" default:"tcp://*:5556"`
	Topic     string   `help:"ZMQ Topic" default:"flow"`
	SourceId  SourceId `help:"NetFlow SourceId (0-255)" default:"0"`
	Format    string   `short:"f" help:"Output format [tlv|json|jcompress|proto] for ZMQ." enum:"tlv,json,jcompress,proto" default:"tlv"`
	Workers   int      `short:"w" help:"Number of NetFlow workers" default:"2"`

	LogLevel  string `short:"l" help:"Log level [error|warn|info|debug|trace]" default:"info" enum:"error,warn,info,debug,trace"`
	LogFormat string `help:"Log format [default|json]" default:"default" enum:"default,json"`

	Version bool `short:"v" help:"Print version and copyright info"`
}

func LoadMappingYaml() (*protoproducer.ProducerConfig, error) {
	config := &protoproducer.ProducerConfig{}
	dec := yaml.NewDecoder(strings.NewReader(localformatters.MappingYaml))
	err := dec.Decode(config)
	return config, err
}

// This entire main() is heavily based on cmd/main.go from netsampler/goflow2.
// It can probably be simplified a bit more, but it works for now.
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
	switch rctx.cli.LogFormat {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{})
	case "default":
		log.Debugf("Using default log style")
	}

	log.SetLevel(lvl)
	localformatters.SetLogger(log)
	localtransport.SetLogger(log)

	var msgType localtransport.MsgFormat
	var formatter *format.Format

	compress := false // For now, only compressing JSON.

	switch rctx.cli.Format {
	case "tlv":
		msgType = localtransport.TLV
		formatter, err = format.FindFormat("ntoptlv")
		log.Info("Using ntopng TLV format for ZMQ")
	case "protobuf":
		msgType = localtransport.PBUF
		log.Fatal("Protobuf not yet supported with goflow2")
	case "jcompress":
		compress = true
		log.Info("Using ntopng compressed JSON format for ZMQ")
		fallthrough
	case "json":
		msgType = localtransport.JSON
		formatter, err = format.FindFormat("ntopjson")
		log.Info("Using ntopng JSON format for ZMQ")
	default:
		log.Fatal("Unknown output format")
	}

	if err != nil {
		log.Fatal("Avail formatters:", format.GetFormats(), err)
	}

	localtransport.RegisterZmq(rctx.cli.ListenZmq, msgType, int(rctx.cli.SourceId), compress)

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
		log.Fatal("error loading mapping config", err)
	}

	cfgm, err := cfgProducer.Compile() // converts configuration into a format that can be used by a protobuf producer
	if err != nil {
		log.Fatal(err)
	}

	flowProducer, err = protoproducer.CreateProtoProducer(cfgm, protoproducer.CreateSamplingSystem)
	if err != nil {
		log.Fatal("error creating producer", err)
	}

	// intercept panic and generate an error
	flowProducer = debug.WrapPanicProducer(flowProducer)
	// wrap producer with Prometheus metrics
	flowProducer = metrics.WrapPromProducer(flowProducer)

	wg := &sync.WaitGroup{}

	var collecting bool
	// Note that goflow2 doesn't yet support a /templates endpoint. We probably should add that.
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/__health", func(wr http.ResponseWriter, r *http.Request) {
		if !collecting {
			wr.WriteHeader(http.StatusServiceUnavailable)
			if _, err := wr.Write([]byte("Not OK\n")); err != nil {
				log.Error("error writing HTTP: ", err)
			}
		} else {
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write([]byte("OK\n")); err != nil {
				log.Error("error writing HTTP: ", err)

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
				log.Fatal("HTTP server error", err.Error())
			}
			log.Info("Closed HTTP server")
		}()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	var receivers []*utils.UDPReceiver
	var pipes []utils.FlowPipe

	q := make(chan bool)

	Nfv9Ip, Nfv9Port := rctx.cli.Listen.Value()

	// Goflow2 UDPReceiver config allows for more complexity, we're just using one socket and however many
	// workers were on the command-line.
	numSockets := 1
	numWorkers := rctx.cli.Workers
	queueSize := 1000000

	log.Info("Starting collection. It may take several minutes for the first flows to appear in ntopng.")

	cfg := &utils.UDPReceiverConfig{
		Sockets:          numSockets,
		Workers:          numWorkers,
		QueueSize:        queueSize,
		Blocking:         false,
		ReceiverCallback: metrics.NewReceiverMetric(),
	}
	recv, err := utils.NewUDPReceiver(cfg)
	if err != nil {
		log.Fatal("Error creating UDP receiver", err.Error())
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
		log.Fatal("Error starting netflow receiver: ", Nfv9Ip, Nfv9Port)
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
						log.Info("Closed receiver")
						continue
					} else if !errors.Is(err, netflow.ErrorTemplateNotFound) && !errors.Is(err, debug.PanicError) {
						log.Error("Error", err)
						continue
					} else {
						if errors.Is(err, netflow.ErrorTemplateNotFound) {
							log.Debug("Netflow packet received before template was set. Discarding")
						} else if errors.Is(err, debug.PanicError) {
							var pErrMsg *debug.PanicErrorMessage
							log.Error("Intercepted panic", pErrMsg)
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
			log.Error("Error stopping receiver", err)
		}
	}
	// then stop pipe
	for _, pipe := range pipes {
		pipe.Close()
	}
	// close producer
	flowProducer.Close()
	// close transporter (eg: flushes message to Kafka) ignore errors, we're exiting anyway
	_ = transporter.Close()
	log.Info("Transporter closed")
	// close http server (prometheus + health check)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Error shutting-down HTTP server", err)
	}
	cancel()
	close(q) // close errors
	wg.Wait()
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
