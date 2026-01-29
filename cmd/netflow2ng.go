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
	"github.com/synfinatic/netflow2ng/collector"
	"github.com/synfinatic/netflow2ng/dedup"
	localformatters "github.com/synfinatic/netflow2ng/formatter"
	"github.com/synfinatic/netflow2ng/sampling"
	"github.com/synfinatic/netflow2ng/sflow"
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

const (
	METRICS_NAMESPACE = "netflow2ng"
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
	// NetFlow/IPFIX Configuration
	Listen  Address `short:"a" help:"NetFlow/IPFIX listen address:port" default:"0.0.0.0:2055"`
	Reuse   bool    `help:"Enable SO_REUSEPORT for NetFlow/IPFIX listen port"`
	Workers int     `short:"w" help:"Number of NetFlow workers" default:"2"`

	// sFlow Configuration
	SFlowListen  Address `help:"sFlow listen address:port (empty to disable)" default:""`
	SFlowWorkers int     `help:"Number of sFlow workers" default:"2"`

	// Metrics/Health
	Metrics Address `short:"m" help:"Metrics listen address" default:"0.0.0.0:8080"`

	// ZMQ Configuration
	ListenZmq      string `short:"z" help:"ZMQ bind address(es), comma-separated for fan-out" default:"tcp://*:5556"`
	FanoutStrategy string `help:"ZMQ fan-out strategy [hash|round-robin]" enum:"hash,round-robin" default:"hash"`
	Topic          string `help:"ZMQ Topic" default:"flow"`
	SourceId       SourceId `help:"NetFlow SourceId (0-255)" default:"0"`
	Format         string `short:"f" help:"Output format [tlv|json|jcompress|proto] for ZMQ." enum:"tlv,json,jcompress,proto" default:"tlv"`

	// Sampling Configuration
	DisableUpscaling bool `help:"Disable sampling rate upscaling (use when exporters pre-scale)"`
	DefaultSampleRate int `help:"Default sampling rate when not reported by exporter" default:"1"`

	// Deduplication Configuration
	DedupEnabled bool          `help:"Enable flow deduplication" default:"false"`
	DedupMaxSize int           `help:"Maximum dedup cache size" default:"100000"`
	DedupTTL     time.Duration `help:"Dedup cache entry TTL" default:"60s"`

	// Queue Configuration
	QueueSize int `help:"Packet queue size" default:"1000000"`

	// Logging
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

func main() {
	var err error
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       false,
	})

	parser := kong.Must(
		&rctx.cli,
		kong.Name("netflow2ng"),
		kong.Description("High-throughput NetFlow v9/IPFIX/sFlow collector for ntopng"),
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
	collector.SetLogger(log)
	sampling.SetLogger(log)
	dedup.SetLogger(log)
	sflow.SetLogger(log)

	// Initialize sampling tracker
	samplingTracker := sampling.NewSamplingTracker(&sampling.SamplingTrackerConfig{
		DefaultRate:    uint32(rctx.cli.DefaultSampleRate),
		ScalingEnabled: !rctx.cli.DisableUpscaling,
		Metrics:        sampling.NewSamplingMetrics(METRICS_NAMESPACE),
	})

	// Initialize dedup cache if enabled
	var dedupCache *dedup.DedupCache
	if rctx.cli.DedupEnabled {
		dedupCache = dedup.NewDedupCache(&dedup.DedupCacheConfig{
			MaxSize: rctx.cli.DedupMaxSize,
			TTL:     rctx.cli.DedupTTL,
			Metrics: dedup.NewDedupMetrics(METRICS_NAMESPACE),
		})
		log.WithFields(logrus.Fields{
			"max_size": rctx.cli.DedupMaxSize,
			"ttl":      rctx.cli.DedupTTL,
		}).Info("Flow deduplication enabled")
	}

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

	// Parse ZMQ endpoints and configure transport
	zmqEndpoints := localtransport.ParseZmqEndpoints(rctx.cli.ListenZmq)
	fanoutStrategy := localtransport.ParseFanoutStrategy(rctx.cli.FanoutStrategy)

	localtransport.RegisterZmqWithConfig(&localtransport.ZmqConfig{
		Endpoints:      zmqEndpoints,
		MsgType:        msgType,
		SourceId:       int(rctx.cli.SourceId),
		Compress:       compress,
		FanoutStrategy: fanoutStrategy,
		Topic:          rctx.cli.Topic,
		Metrics:        localtransport.NewZmqMetrics(METRICS_NAMESPACE),
	})

	if len(zmqEndpoints) > 1 {
		log.WithFields(logrus.Fields{
			"endpoints": zmqEndpoints,
			"strategy":  rctx.cli.FanoutStrategy,
		}).Info("Multi-endpoint ZMQ fan-out configured")
	}

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
	// HTTP server for metrics, health, and templates
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

	// Sampling info endpoint
	http.HandleFunc("/sampling", func(wr http.ResponseWriter, r *http.Request) {
		info := samplingTracker.GetAllSamplingInfo()
		wr.Header().Add("Content-Type", "application/json")
		if body, err := json.MarshalIndent(info, "", "  "); err != nil {
			log.Error("error writing JSON body for /sampling", err)
			wr.WriteHeader(http.StatusInternalServerError)
		} else {
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write(body); err != nil {
				log.Error("error writing HTTP", err)
			}
		}
	})

	// Dedup stats endpoint
	if dedupCache != nil {
		http.HandleFunc("/dedup", func(wr http.ResponseWriter, r *http.Request) {
			stats := map[string]interface{}{
				"cache_size": dedupCache.Size(),
				"max_size":   rctx.cli.DedupMaxSize,
				"ttl":        rctx.cli.DedupTTL.String(),
			}
			wr.Header().Add("Content-Type", "application/json")
			if body, err := json.MarshalIndent(stats, "", "  "); err != nil {
				log.Error("error writing JSON body for /dedup", err)
				wr.WriteHeader(http.StatusInternalServerError)
			} else {
				wr.WriteHeader(http.StatusOK)
				if _, err := wr.Write(body); err != nil {
					log.Error("error writing HTTP", err)
				}
			}
		})
	}

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

	Nfv9Ip, Nfv9Port := rctx.cli.Listen.Value()

	// Goflow2 UDPReceiver config allows for more complexity, we're just using one socket and however many
	// workers were on the command-line.
	numSockets := 1
	numWorkers := rctx.cli.Workers
	queueSize := rctx.cli.QueueSize

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

	http.HandleFunc("/templates", func(wr http.ResponseWriter, r *http.Request) {
		templates := nfPipe.GetTemplatesForAllSources()
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
	})

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

	// Start sFlow collector if configured
	var sflowCollector *sflow.SFlowCollector
	if string(rctx.cli.SFlowListen) != "" {
		sflowIP, sflowPort := rctx.cli.SFlowListen.Value()

		// Create flow handler that sends sFlow data to the same transport
		sflowHandler := func(msg *sflow.FlowMessage) error {
			// Convert to goflow2 format and send through existing pipeline
			gfMsg := sflow.ConvertToGoflowMessage(msg)

			// Apply sampling upscaling if enabled
			if !rctx.cli.DisableUpscaling && msg.SamplingRate > 1 {
				gfMsg.Bytes *= uint64(msg.SamplingRate)
				gfMsg.Packets *= uint64(msg.SamplingRate)
			}

			// Format and send
			key, data, err := formatter.Format(gfMsg)
			if err != nil {
				return err
			}
			return transporter.Send(key, data)
		}

		sflowCollector = sflow.NewSFlowCollector(&sflow.SFlowCollectorConfig{
			ListenAddr:      sflowIP,
			ListenPort:      sflowPort,
			NumWorkers:      rctx.cli.SFlowWorkers,
			QueueSize:       rctx.cli.QueueSize,
			SamplingTracker: samplingTracker,
			FlowHandler:     sflowHandler,
			Metrics:         sflow.NewSFlowMetrics(METRICS_NAMESPACE),
			PoolMetrics:     collector.NewPoolMetrics(METRICS_NAMESPACE + "_sflow"),
		})

		if err := sflowCollector.Start(); err != nil {
			log.WithError(err).Fatal("Error starting sFlow collector")
		}

		log.WithFields(logrus.Fields{
			"addr": sflowIP,
			"port": sflowPort,
		}).Info("sFlow collector started")
	}

	collecting = true

	<-c

	collecting = false

	// Stop sFlow collector if running
	if sflowCollector != nil {
		if err := sflowCollector.Stop(); err != nil {
			log.WithError(err).Error("Error stopping sFlow collector")
		}
	}

	// stops receivers first, udp sockets will be down
	_ = nfRecv.Stop()
	// then stop pipe
	nfPipe.Close()
	flowProducer.Close()
	// close transporter (eg: flushes message to Kafka) ignore errors, we're exiting anyway
	_ = transporter.Close()
	log.Info("Transporter closed")

	// Stop dedup cache cleanup
	if dedupCache != nil {
		dedupCache.Stop()
	}

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
	fmt.Println("\nProtocol Support:")
	fmt.Println("  - NetFlow v9")
	fmt.Println("  - IPFIX (NetFlow v10)")
	fmt.Println("  - sFlow v5")
	fmt.Println("\nFeatures:")
	fmt.Println("  - Multi-endpoint ZMQ fan-out (hash/round-robin)")
	fmt.Println("  - Per-exporter sampling rate tracking and upscaling")
	fmt.Println("  - Flow deduplication with configurable TTL")
	fmt.Println("  - High-throughput worker pool architecture")
}
