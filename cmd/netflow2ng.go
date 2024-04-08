package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"

	// decoders

	// various formatters
	"github.com/netsampler/goflow2/v2/format"
	_ "github.com/netsampler/goflow2/v2/format/binary"
	_ "github.com/netsampler/goflow2/v2/format/json"
	_ "github.com/netsampler/goflow2/v2/format/text"

	// various transports
	"github.com/netsampler/goflow2/v2/transport"
	//	_ "github.com/netsampler/goflow2/v2/transport/file"
	//	_ "github.com/netsampler/goflow2/v2/transport/kafka"

	// various producers

	rawproducer "github.com/netsampler/goflow2/v2/producer/raw"

	// core libraries

	"github.com/netsampler/goflow2/v2/utils"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	// log "github.com/sirupsen/logrus"

	"github.com/synfinatic/netflow2ng/transport/ntopng"
)

var (
	COPYRIGHT_YEAR string = "2020-2024"
	Version        string = "unknown"
	Buildinfos     string = "unknown"
	Delta          string = ""
	CommitID       string = "unknown"
	Tag            string = "NO-TAG"
	rctx           RunContext
)

type RunContext struct {
	Kctx *kong.Context
	cli  CLI
}

type SourceId int

func (s *SourceId) Validate() error {
	if *s < 0 || *s > 255 {
		return fmt.Errorf("Must be betweeen 0 and 255")
	}
	return nil
}

type Address string

func (a *Address) Value() (string, int) {
	var port int64
	var err error

	listen := strings.SplitN(string(*a), ":", 2)
	if port, err = strconv.ParseInt(listen[1], 10, 16); err != nil {
		slog.Error("Unable to parse", "--listen", string(*a))
		os.Exit(1)
	}
	return listen[0], int(port)
}

type CLI struct {
	Listen Address `kong:"short='a',help='NetFlow/IPFIX listen address:port',default='0.0.0.0:2055'"`

	Metrics string `kong:"short='m',help='Metrics listen address',default='0.0.0.0:8080'"`

	ListenZmq string   `kong:"short='z',help='proto://IP:Port to listen on for ZMQ connections',default='tcp://*:5556'"`
	Topic     string   `kong:"help='ZMQ Topic',default='flow'"`
	SourceId  SourceId `kong:"help='NetFlow SourceId (0-255)',default=0"`
	Compress  bool     `kong:"help='Compress ZMQ JSON data',xor='zmq-data'"`
	Protobuf  bool     `kong:"help='Use ProtoBuff instead of JSQN for ZMQ',xor='zmq-data'"`

	Workers   int    `kong:"short='w',help='Number of NetFlow workers',default=1"`
	LogLevel  string `kong:"short='l',help='Log level [error|warn|info|debug|trace]',default='info',enum='error,warn,info,debug,trace'"`
	LogFormat string `kong:"short='f',help='Log format [text|json]',default='text',enum='text,json'"`
	Version   bool   `kong:"short='v',help='Print version and copyright info'"`
}

/*
func httpServer(state *utils.StateNetFlow, metricsAddress string) {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/templates", state.ServeHTTPTemplates)
	log.Fatal(http.ListenAndServe(metricsAddress, nil))
}
*/

func main() {
	var err error

	parser := kong.Must(
		&rctx.cli,
		kong.Name("netflow2ng"),
		kong.Description("NetFlow v9 Proxy for ntopng"),
		kong.UsageOnError(),
	)

	rctx.Kctx, err = parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	var logger *slog.Logger
	var level slog.Level = getLogLevel(rctx.cli.LogLevel)
	switch rctx.cli.LogFormat {
	case "text":
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	case "json":
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	default:
		logger.Error("invalid log format", "format", rctx.cli.LogFormat)
		os.Exit(1)
	}
	slog.SetDefault(logger)

	if rctx.cli.Version {
		PrintVersion()
		os.Exit(0)
	}

	n := ntopng.NewNtopngDriver(rctx.cli.ListenZmq, uint(rctx.cli.SourceId))
	n.Register()

	formatter, err := format.FindFormat("json")
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	transporter, err := transport.FindTransport("ntopng")
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	flowProducer = &rawproducer.RawProducer{}

	wg := &sync.WaitGroup{}

	var collecting bool
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/__health", func(wr http.ResponseWriter, r *http.Request) {
		if !collecting {
			wr.WriteHeader(http.StatusServiceUnavailable)
			if _, err := wr.Write([]byte("Not OK\n")); err != nil {
				slog.Error("error writing HTTP", "err", err.Error())
			}
		} else {
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write([]byte("OK\n")); err != nil {
				slog.Error("error writing HTTP", "err", err.Error())
			}
		}
	})
	srv := http.Server{
		Addr:              rctx.cli.Metrics,
		ReadHeaderTimeout: time.Second * 5,
	}
	if *Addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := srv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("HTTP server error", "err", err)
			}
			slog.Info("closed HTTP server")
		}()
	}

	////////////
	var defaultTransport utils.Transport
	defaultTransport = &utils.DefaultLogTransport{}

	runtime.GOMAXPROCS(runtime.NumCPU())

	slog.Info("Starting netflow2ng")

	s := &utils.StateNetFlow{
		Transport: defaultTransport,
		Logger:    slog,
	}

	// go httpServer(s, string(rctx.cli.Metrics))

	if s.Transport, err = StartZmqProducer(); err != nil {
		slog.Error("unable to start ZMQ", "err", err)
		os.Exit(1)
	}

	ip, port := rctx.cli.Listen.Value()

	slog.Info("Starting NetFlow listener",
		"Type", "NetFlow",
		"Listening on UDP", rctx.cli.Listen,
	)

	if err = s.FlowRoutine(rctx.cli.Workers, ip, port, true); err != nil {
		slog.Error("could not listen to UDP", "err", err)
		os.Exit(1)
	}
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
