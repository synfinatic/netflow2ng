package transport

// A CURVE key mismatch is invisible at the ZMQ API: Send() keeps succeeding and
// the collector simply never receives anything.  libzmq does report the failed
// handshake through a socket monitor though, which is the only hook netflow2ng
// has for turning that silent failure into a log line.

import (
	"fmt"
	"syscall"
	"time"

	zmq "github.com/pebbe/zmq4"
)

// monitorAddr is the inproc endpoint libzmq publishes socket events on. Each
// driver owns its own ZMQ context, so a fixed name cannot collide.
const monitorAddr = "inproc://netflow2ng-monitor"

// monitorPollInterval bounds how long a shutdown waits on the monitor goroutine.
const monitorPollInterval = 200 * time.Millisecond

// shouldLogHandshakeFailure reports whether failure number n deserves a warning.
// A collector with the wrong key reconnects several times a second, so logging
// every failure would bury everything else in the log.
func shouldLogHandshakeFailure(n int) bool {
	switch {
	case n <= 3:
		return true
	case n < 100:
		return n%10 == 0
	default:
		return n%100 == 0
	}
}

// startMonitor subscribes to the publisher's handshake events. It must run
// before Bind(): libzmq only reports events for endpoints created afterwards.
func (d *ZmqDriver) startMonitor() error {
	events := zmq.EVENT_HANDSHAKE_SUCCEEDED | zmq.EVENT_HANDSHAKE_FAILED_NO_DETAIL |
		zmq.EVENT_HANDSHAKE_FAILED_PROTOCOL | zmq.EVENT_HANDSHAKE_FAILED_AUTH
	if err := d.publisher.Monitor(monitorAddr, events); err != nil {
		return fmt.Errorf("unable to monitor the ZMQ socket: %w", err)
	}

	sock, err := d.context.NewSocket(zmq.PAIR)
	if err != nil {
		return fmt.Errorf("unable to create the ZMQ monitor socket: %w", err)
	}
	if err = sock.SetRcvtimeo(monitorPollInterval); err != nil {
		_ = sock.Close()
		return fmt.Errorf("unable to set the ZMQ monitor timeout: %w", err)
	}
	if err = sock.Connect(monitorAddr); err != nil {
		_ = sock.Close()
		return fmt.Errorf("unable to connect the ZMQ monitor socket: %w", err)
	}

	d.monitor = sock
	d.monitorStop = make(chan struct{})
	d.monitorDone = make(chan struct{})
	go d.watchHandshakes()
	return nil
}

// stopMonitor shuts the monitor goroutine down and waits for it to release the
// monitor socket, so Close() can terminate the context without racing it.
func (d *ZmqDriver) stopMonitor() {
	if d.monitorStop == nil {
		return
	}
	close(d.monitorStop)
	<-d.monitorDone
	d.monitor, d.monitorStop, d.monitorDone = nil, nil, nil
}

func (d *ZmqDriver) watchHandshakes() {
	defer close(d.monitorDone)
	defer func() { _ = d.monitor.Close() }()

	failures := 0
	for {
		select {
		case <-d.monitorStop:
			return
		default:
		}

		event, _, _, err := d.monitor.RecvEvent(0)
		if err != nil {
			if zmq.AsErrno(err) == zmq.Errno(syscall.EAGAIN) {
				continue // poll timeout: re-check for shutdown and keep waiting
			}
			return // the socket or its context is going away
		}

		if event&zmq.EVENT_HANDSHAKE_SUCCEEDED != 0 {
			failures = 0
			d.logHandshakeSuccess()
			continue
		}

		failures++
		if shouldLogHandshakeFailure(failures) {
			d.logHandshakeFailure(failures)
		}
	}
}

func (d *ZmqDriver) logHandshakeSuccess() {
	if d.encryption == nil {
		log.Infof("A collector connected on %s in cleartext", d.listenAddress)
		return
	}
	log.Infof("A collector completed the ZMQ CURVE handshake on %s", d.listenAddress)
}

func (d *ZmqDriver) logHandshakeFailure(failures int) {
	if d.encryption == nil {
		log.Warnf("A collector failed the ZMQ handshake on %s (failure #%d). netflow2ng is "+
			"running with --zmq-disable-encryption; ntopng 6.7.280831 and later expect "+
			"encrypted flows unless they are also started with --zmq-disable-encryption.",
			d.listenAddress, failures)
		return
	}
	log.Warnf("ZMQ CURVE handshake failed on %s (failure #%d): the collector does not hold "+
		"the private key matching public key %s. Compare --zmq-encryption-key against "+
		"ntopng's zmq-key.pub, or run both sides with --zmq-disable-encryption.",
		d.listenAddress, failures, d.encryption.ServerKey)
}
