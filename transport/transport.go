package transport

import (
	"sync"

	"github.com/netsampler/goflow2/v2/transport"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func SetLogger(l *logrus.Logger) {
	log = l
}

func RegisterZmq(zmqListen string, msgType MsgFormat, sourceId int, compress bool) {
	z := &ZmqDriver{
		listenAddress: zmqListen,
		sourceId:      sourceId,
		msgType:       msgType,
		compress:      compress,
		lock:          &sync.RWMutex{},
	}
	transport.RegisterTransportDriver("zmq", z)
}
