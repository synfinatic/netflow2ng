package ntopng

var MessageId uint32 = 0 // Every ZMQ message we send should have a uniq ID

/*
 * For more info on this you'll want to read:
 * include/ntop_typedefs.h, include/ntop_defines.h & src/ZMQCollectorInterface.cpp from
 * https://github.com/ntop/ntopng
 */
const ZMQ_MSG_VERSION = 2 // ntopng message version 2
const ZMQ_TOPIC = "flow"  // ntopng only really cares about the first character!

type ZmqHeader struct {
	url       string
	version   uint8
	source_id uint8
	length    uint16
	msg_id    uint32
}

func NewZmqHeader(length uint16, source_id uint8) *ZmqHeader {
	z := &ZmqHeader{
		url:       ZMQ_TOPIC,
		version:   ZMQ_MSG_VERSION,
		source_id: source_id,
		length:    length,
		msg_id:    MessageId,
	}
	MessageId++
	return z
}

func (z *ZmqHeader) Bytes() ([]byte, error) {
	buf := make([]byte, 24)
	urlLen := len(z.url)
	copy(buf[0:16], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // 16 bytes of 0
	copy(buf[0:urlLen], z.url)
	buf[16] = byte(z.version)
	buf[17] = byte(z.source_id)
	buf[18] = byte(z.length >> 8)
	buf[19] = byte(z.length & 0xff)
	buf[20] = byte(z.msg_id >> 24)
	buf[21] = byte(z.msg_id >> 16)
	buf[22] = byte(z.msg_id >> 8)
	buf[23] = byte(z.msg_id & 0xff)
	return buf, nil
}
