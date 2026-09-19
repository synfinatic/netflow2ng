package transport

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	zmq "github.com/pebbe/zmq4"
	"github.com/sirupsen/logrus"
)

func TestShouldLogHandshakeFailure(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want bool
	}{
		{"first failure is always loud", 1, true},
		{"second failure is still loud", 2, true},
		{"third failure is still loud", 3, true},
		{"fourth failure is suppressed", 4, false},
		{"ninth failure is suppressed", 9, false},
		{"every tenth failure is loud again", 10, true},
		{"eleventh failure is suppressed", 11, false},
		{"ninetieth failure is loud", 90, true},
		{"past a hundred only every hundredth is loud", 110, false},
		{"two hundredth failure is loud", 200, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldLogHandshakeFailure(tc.n); got != tc.want {
				t.Errorf("shouldLogHandshakeFailure(%d) = %v, want %v", tc.n, got, tc.want)
			}
		})
	}
}

// syncBuffer is an io.Writer safe to read while the monitor goroutine writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// captureTransportLog redirects the package logger for the duration of a test.
// Register it first so its cleanup runs last, after any driver has been closed.
func captureTransportLog(t *testing.T) *syncBuffer {
	t.Helper()
	previous := log
	buf := &syncBuffer{}
	l := logrus.New()
	l.SetOutput(buf)
	l.SetLevel(logrus.DebugLevel)
	SetLogger(l)
	t.Cleanup(func() { SetLogger(previous) })
	return buf
}

func waitForLog(t *testing.T, buf *syncBuffer, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("log never contained %q within %s; got:\n%s", want, timeout, buf.String())
}

// TestZmqDriver_CurveHandshakeFailure_IsLogged is the whole point of the socket
// monitor: without it a mismatched key produces no output on either side.
func TestZmqDriver_CurveHandshakeFailure_IsLogged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}
	if !zmq.HasCurve() {
		t.Skip("libzmq built without CURVE support")
	}
	const addr = "tcp://127.0.0.1:15581"

	buf := captureTransportLog(t)

	wrongPub, _, err := zmq.NewCurveKeypair()
	if err != nil {
		t.Fatalf("unable to generate a test keypair: %v", err)
	}
	d := newZmqDriver(addr, TLV, 42, false, &EncryptionConfig{ServerKey: wrongPub})
	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// The collector holds the built-in default keypair, not wrongPub.
	newNtopngStyleSubscriber(t, addr, testNtopngDefaultPrivKey)

	waitForLog(t, buf, "CURVE handshake failed", 10*time.Second)
	if !strings.Contains(buf.String(), "--zmq-encryption-key") {
		t.Errorf("handshake failure log does not name the flag to fix: %s", buf.String())
	}
}

// TestZmqDriver_CurveHandshakeSuccess_IsLogged gives operators positive
// confirmation that a collector actually completed the handshake.
func TestZmqDriver_CurveHandshakeSuccess_IsLogged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}
	if !zmq.HasCurve() {
		t.Skip("libzmq built without CURVE support")
	}
	const addr = "tcp://127.0.0.1:15582"

	buf := captureTransportLog(t)

	d := newZmqDriver(addr, TLV, 42, false, &EncryptionConfig{ServerKey: DefaultNtopngPublicKey})
	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	newNtopngStyleSubscriber(t, addr, testNtopngDefaultPrivKey)

	waitForLog(t, buf, "completed the ZMQ CURVE handshake", 10*time.Second)
}
