package main

import (
	"context"
	"encoding/json"
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
	COPYRIGHT_YEAR string = "2020-2026"
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

func (a *Address) Value() (string, int, error) {
	listen := strings.SplitN(string(*a), ":", 2)
	if len(listen) != 2 {
		return "", 0, fmt.Errorf("invalid address format (expected host:port): %s", string(*a))
	}
	port, err := strconv.ParseInt(listen[1], 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("unable to parse port in address: %s", string(*a))
	}
	return listen[0], int(port), nil
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

// templateSource is the interface for retrieving NetFlow templates (satisfied by *utils.NetFlowPipe).
type templateSource interface {
	GetTemplatesForAllSources() map[string]map[uint64]interface{}
}

// setupLogging configures the logger level and format, and propagates it to sub-packages.
func setupLogging(logFormat, logLevel string, l *logrus.Logger) {
	lvl, _ := logrus.ParseLevel(logLevel)
	switch logFormat {
	case "json":
		l.SetFormatter(&logrus.JSONFormatter{})
	case "default":
		l.Debugf("Using default log style")
	}
	l.SetLevel(lvl)
	localformatters.SetLogger(l)
	localtransport.SetLogger(l)
}

// selectFormat returns the MsgFormat, registered formatter, compress flag, and any error.
// Returns an error instead of calling log.Fatal so callers can handle it in tests.
func selectFormat(formatStr string, l *logrus.Logger) (localtransport.MsgFormat, *format.Format, bool, error) {
	var msgType localtransport.MsgFormat
	var f *format.Format
	var err error
	compress := false

	switch formatStr {
	case "tlv":
		msgType = localtransport.TLV
		if f, err = format.FindFormat("ntoptlv"); err != nil {
			return 0, nil, false, fmt.Errorf("avail formatters: %v: %w", format.GetFormats(), err)
		}
		l.Info("Using ntopng TLV format for ZMQ")
	case "proto", "protobuf":
		return localtransport.PBUF, nil, false, errors.New("protobuf not yet supported with goflow2")
	case "jcompress":
		compress = true
		l.Info("Using ntopng compressed JSON format for ZMQ")
		fallthrough
	case "json":
		msgType = localtransport.JSON
		if f, err = format.FindFormat("ntopjson"); err != nil {
			return 0, nil, false, fmt.Errorf("avail formatters: %v: %w", format.GetFormats(), err)
		}
		l.Info("Using ntopng JSON format for ZMQ")
	default:
		return 0, nil, false, fmt.Errorf("unknown output format: %s", formatStr)
	}

	return msgType, f, compress, nil
}

// newHealthHandler returns an HTTP handler for the /__health endpoint.
func newHealthHandler(collecting *bool) http.HandlerFunc {
	return func(wr http.ResponseWriter, r *http.Request) {
		if !*collecting {
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
	}
}

// newTemplatesHandler returns an HTTP handler for the /templates endpoint.
func newTemplatesHandler(ts templateSource) http.HandlerFunc {
	return func(wr http.ResponseWriter, r *http.Request) {
		templates := ts.GetTemplatesForAllSources()
		if body, err := json.MarshalIndent(templates, "", "  "); err != nil {
			log.Error("error writing JSON body for /templates", err)
			wr.WriteHeader(http.StatusInternalServerError)
			if _, err := wr.Write([]byte("Internal Server Error\n")); err != nil {
				log.Error("error writing HTTP", err)
			}
		} else {
			wr.Header().Add("Content-Type", "application/json")
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write(body); err != nil {
				log.Error("error writing HTTP", err)
			}
		}
	}
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

	setupLogging(rctx.cli.LogFormat, rctx.cli.LogLevel, log)

	msgType, formatter, compress, err := selectFormat(rctx.cli.Format, log)
	if err != nil {
		log.Fatal(err)
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
	http.HandleFunc("/__health", newHealthHandler(&collecting))
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
	q := make(chan bool)

	Nfv9Ip, Nfv9Port, err := rctx.cli.Listen.Value()
	if err != nil {
		log.Fatal(err)
	}

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
	nfRecv, err := utils.NewUDPReceiver(cfg)
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
	nfPipe := utils.NewNetFlowPipe(cfgPipe)

	http.HandleFunc("/templates", newTemplatesHandler(nfPipe))

	decodeFunc = nfPipe.DecodeFlow
	// intercept panic and generate error
	decodeFunc = debug.PanicDecoderWrapper(decodeFunc)
	// wrap decoder with Prometheus metrics
	decodeFunc = metrics.PromDecoderWrapper(decodeFunc, "netflow")

	// starts receivers
	// the function either returns an error
	if err := nfRecv.Start(Nfv9Ip, Nfv9Port, decodeFunc); err != nil {
		log.Fatal("Error starting netflow receiver: ", Nfv9Ip, Nfv9Port)
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-q:
					return
				case err := <-nfRecv.Errors():
					if errors.Is(err, net.ErrClosed) {
						log.Info("Closed receiver")
						continue
					} else if !errors.Is(err, netflow.ErrorTemplateNotFound) && !errors.Is(err, &debug.PanicErrorMessage{}) {
						log.Error("Error", err)
						continue
					} else {
						if errors.Is(err, netflow.ErrorTemplateNotFound) {
							log.Debug("Netflow packet received before template was set. Discarding")
							log.Trace("More info: ", err)
						} else if errors.Is(err, &debug.PanicErrorMessage{}) {
							var pErrMsg *debug.PanicErrorMessage
							log.Error("Intercepted panic", pErrMsg)
						} else {
							log.Error(err)
						}
					}
				}
			}
		}()
	}

	collecting = true

	<-c

	collecting = false

	// stops receivers first, udp sockets will be down
	_ = nfRecv.Stop()
	// then stop pipe
	nfPipe.Close()
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
