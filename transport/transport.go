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

func RegisterZmq(zmqListen string, msgType MsgFormat, sourceId int, compress bool, encryption *EncryptionConfig) {
	transport.RegisterTransportDriver("zmq", newZmqDriver(zmqListen, msgType, sourceId, compress, encryption))
}

// newZmqDriver builds the ZMQ transport driver. Split out from RegisterZmq so
// the wiring can be asserted without touching goflow2's global registry.
func newZmqDriver(zmqListen string, msgType MsgFormat, sourceId int, compress bool, encryption *EncryptionConfig) *ZmqDriver {
	return &ZmqDriver{
		listenAddress: zmqListen,
		sourceId:      sourceId,
		msgType:       msgType,
		compress:      compress,
		encryption:    encryption,
		lock:          &sync.RWMutex{},
		messageId:     1,
	}
}
