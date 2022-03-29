package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cloudflare/goflow/v3/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
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
		log.Fatalf("Unable to parse: --listen %s", string(*a))
	}
	return listen[0], int(port)
}

type CLI struct {
	Listen Address `kong:"short='a',help='NetFlow/IPFIX listen address:port',default='0.0.0.0:2055'"`
	Reuse  bool    `kong:"help='Enable SO_REUSEPORT for NetFlow/IPFIX listen port'"`

	Metrics Address `kong:"short='m',help='Metrics listen address',default='0.0.0.0:8080'"`

	ListenZmq string   `kong:"short='z',help='proto://IP:Port to listen on for ZMQ connections',default='tcp://*:5556'"`
	Topic     string   `kong:"help='ZMQ Topic',default='flow'"`
	SourceId  SourceId `kong:"help='NetFlow SourceId (0-255)',default=0"`
	Compress  bool     `kong:"help='Compress ZMQ JSON data',xor='zmq-data'"`
	Protobuf  bool     `kong:"help='Use ProtoBuff instead of JSQN for ZMQ',xor='zmq-data'"`

	Workers   int    `kong:"short='w',help='Number of NetFlow workers',default=1"`
	LogLevel  string `kong:"short='l',help='Log level [error|warn|info|debug|trace]',default='info',enum='error,warn,info,debug,trace'"`
	LogFormat string `kong:"short='f',help='Log format [default|json]',default='default',enum='default,json'"`
	Version   bool   `kong:"short='v',help='Print version and copyright info'"`
}

func httpServer(state *utils.StateNetFlow, metricsAddress string) {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/templates", state.ServeHTTPTemplates)
	log.Fatal(http.ListenAndServe(metricsAddress, nil))
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
