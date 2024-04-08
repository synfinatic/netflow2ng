package ntopng

import (
	"flag"
	"fmt"
	"log/slog"

	"github.com/netsampler/goflow2/v2/transport"
	zmq "github.com/pebbe/zmq4"
)

type NtopngDriver struct {
	context   *zmq.Context
	listen    string // proto://IP:Port to listen on for ZMQ connections
	publisher *zmq.Socket
	source_id uint
	UseFlags  bool // if set, Prepare() will add flags to the flagset
}

// Create a new NtopngDriver with the given listen address and source_id
// source_id 0-255 and listen is the ZMQ connection string
func NewNtopngDriver(listen string, source_id uint) *NtopngDriver {
	return &NtopngDriver{
		listen:    listen,
		source_id: source_id,
		UseFlags:  false,
	}
}

// Register the NtopngDriver with the TransportDriver interface
func (nt *NtopngDriver) Register() {
	transport.RegisterTransportDriver("ntopng", nt)
}

// Implement the TransportDriver interface
func (nt *NtopngDriver) Prepare() error {
	if nt.UseFlags {
		flag.StringVar(&nt.listen, "ntopng.listen", "tcp://0.0.0.0:5556", "Listen for ZMQ connections from ntopng")
		flag.UintVar(&nt.source_id, "ntopng.source_id", 0, "Source ID for ZMQ messages")
	}
	return nil
}

// Initialize the NtopngDriver
func (nt *NtopngDriver) Init() error {
	var err error
	nt.context, err = zmq.NewContext()
	if err != nil {
		return err
	}

	nt.publisher, err = nt.context.NewSocket(zmq.PUB)
	if err != nil {
		return err
	}

	err = nt.publisher.Bind(nt.listen)
	if err != nil {
		slog.Error("Unable to bind", "err", err.Error())
		return err
	}
	return nil
}

// Close the NtopngDriver
func (nt *NtopngDriver) Close() error {
	return nt.publisher.Close()
}

// Send data to ntopng
func (nt *NtopngDriver) Send(key, data []byte) error {
	msgLen := uint16(len(data))
	header := NewZmqHeader(msgLen, uint8(nt.source_id))

	// Send the header with the topic first as a multi-part message
	headerBytes, err := header.Bytes()
	if err != nil {
		slog.Error("Unable to serialize header", "err", err.Error())
		return err
	}

	bytes, err := nt.publisher.SendBytes(headerBytes, zmq.SNDMORE)
	if err != nil {
		slog.Error("Unable to send header", "err", err.Error())
		return err
	}

	if bytes != len(headerBytes) {
		slog.Error("Wrote the wrong number of header bytes",
			"sent", len(headerBytes),
			"expected", bytes,
		)
		return fmt.Errorf("%s", "Wrote the wrong number of header bytes")
	}

	// Now send the actual JSON payload
	if _, err = nt.publisher.SendBytes(data, 0); err != nil {
		slog.Error("Unable to send message", "err", err.Error())
		return err
	}

	slog.Debug("sent ZMQ message", "len", msgLen)
	return nil
}
