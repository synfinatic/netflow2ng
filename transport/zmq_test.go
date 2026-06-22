package transport

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	zmq "github.com/pebbe/zmq4"
	"github.com/sirupsen/logrus"
)

func init() {
	// Package-level logger must be set before tests that exercise code paths
	// that call log methods.
	SetLogger(logrus.New())
}

// newTestDriver creates a ZmqDriver without initializing the ZMQ socket.
func newTestDriver(msgType MsgFormat, compress bool, sourceId int) *ZmqDriver {
	return &ZmqDriver{
		listenAddress: "tcp://127.0.0.1:15557",
		sourceId:      sourceId,
		msgType:       msgType,
		compress:      compress,
		lock:          &sync.RWMutex{},
	}
}

// --- zmqHeaderV3.bytes() ---

func TestZmqHeaderV3_Bytes_Length(t *testing.T) {
	h := &zmqHeaderV3{
		url:               ZMQ_TOPIC,
		version:           ZMQ_MSG_VERSION_4,
		flags:             0,
		uncompressed_size: 100,
		compressed_size:   100,
		msg_id:            1,
		source_id:         0,
	}
	b, err := h.bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 16 bytes URL + 1 version + 1 flags + 2 padding + 4 uncompressed + 4 compressed + 4 msg_id + 4 source_id = 36
	if len(b) != 36 {
		t.Errorf("expected 36 bytes, got %d", len(b))
	}
}

// TestZmqHeaderV3_Bytes_URLTooLong verifies that bytes() returns an error when
// the URL field exceeds 16 bytes (the fixed-size header slot).
func TestZmqHeaderV3_Bytes_URLTooLong(t *testing.T) {
	h := &zmqHeaderV3{
		url:     "this_url_is_way_too_long_for_the_16_byte_field",
		version: ZMQ_MSG_VERSION_4,
	}
	_, err := h.bytes()
	if err == nil {
		t.Error("expected error for URL longer than 16 bytes, got nil")
	}
}

func TestZmqHeaderV3_Bytes_URLPadding(t *testing.T) {
	h := &zmqHeaderV3{
		url:     "flow", // 4 chars → padded to 16
		version: ZMQ_MSG_VERSION_4,
	}
	b, err := h.bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Bytes [0:16] are the URL: "flow" followed by 12 null bytes
	if string(b[0:4]) != "flow" {
		t.Errorf("expected URL to start with 'flow', got %q", string(b[0:4]))
	}
	for i := 4; i < 16; i++ {
		if b[i] != 0 {
			t.Errorf("expected null padding at byte %d, got 0x%02x", i, b[i])
		}
	}
}

func TestZmqHeaderV3_Bytes_VersionAndFlags(t *testing.T) {
	h := &zmqHeaderV3{
		url:     ZMQ_TOPIC,
		version: ZMQ_MSG_VERSION_4,
		flags:   ZMQ_MSG_V4_FLAG_TLV | ZMQ_MSG_V4_FLAG_COMPRESSED,
	}
	b, err := h.bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[16] != ZMQ_MSG_VERSION_4 {
		t.Errorf("expected version %d at byte 16, got %d", ZMQ_MSG_VERSION_4, b[16])
	}
	expectedFlags := uint8(ZMQ_MSG_V4_FLAG_TLV | ZMQ_MSG_V4_FLAG_COMPRESSED)
	if b[17] != expectedFlags {
		t.Errorf("expected flags 0x%02x at byte 17, got 0x%02x", expectedFlags, b[17])
	}
}

func TestZmqHeaderV3_Bytes_SizesLittleEndian(t *testing.T) {
	const origSize uint32 = 0x01020304
	const compSize uint32 = 0x05060708
	h := &zmqHeaderV3{
		url:               ZMQ_TOPIC,
		version:           ZMQ_MSG_VERSION_4,
		uncompressed_size: origSize,
		compressed_size:   compSize,
	}
	b, err := h.bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// uncompressed_size at bytes [20:24] in little-endian
	gotOrig := binary.LittleEndian.Uint32(b[20:24])
	if gotOrig != origSize {
		t.Errorf("uncompressed_size: expected 0x%08x, got 0x%08x", origSize, gotOrig)
	}
	// compressed_size at bytes [24:28] in little-endian
	gotComp := binary.LittleEndian.Uint32(b[24:28])
	if gotComp != compSize {
		t.Errorf("compressed_size: expected 0x%08x, got 0x%08x", compSize, gotComp)
	}
}

func TestZmqHeaderV3_Bytes_IDsBigEndian(t *testing.T) {
	const msgID uint32 = 0xDEADBEEF
	const srcID uint32 = 0xCAFEBABE
	h := &zmqHeaderV3{
		url:       ZMQ_TOPIC,
		version:   ZMQ_MSG_VERSION_4,
		msg_id:    msgID,
		source_id: srcID,
	}
	b, err := h.bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// msg_id at bytes [28:32] in big-endian
	gotMsg := binary.BigEndian.Uint32(b[28:32])
	if gotMsg != msgID {
		t.Errorf("msg_id: expected 0x%08x, got 0x%08x", msgID, gotMsg)
	}
	// source_id at bytes [32:36] in big-endian
	gotSrc := binary.BigEndian.Uint32(b[32:36])
	if gotSrc != srcID {
		t.Errorf("source_id: expected 0x%08x, got 0x%08x", srcID, gotSrc)
	}
}

// --- newZmqHeaderV3 flags ---

func TestNewZmqHeaderV3_Flags_TLV(t *testing.T) {
	d := newTestDriver(TLV, false, 0)
	h := d.newZmqHeaderV3(100, 100)
	if h.flags&ZMQ_MSG_V4_FLAG_TLV == 0 {
		t.Error("expected ZMQ_MSG_V4_FLAG_TLV to be set for TLV format")
	}
	if h.flags&ZMQ_MSG_V4_FLAG_COMPRESSED != 0 {
		t.Error("expected ZMQ_MSG_V4_FLAG_COMPRESSED NOT to be set when compress=false")
	}
}

func TestNewZmqHeaderV3_Flags_Compress(t *testing.T) {
	d := newTestDriver(JSON, true, 0)
	h := d.newZmqHeaderV3(100, 50)
	if h.flags&ZMQ_MSG_V4_FLAG_COMPRESSED == 0 {
		t.Error("expected ZMQ_MSG_V4_FLAG_COMPRESSED to be set when compress=true")
	}
	if h.flags&ZMQ_MSG_V4_FLAG_TLV != 0 {
		t.Error("expected ZMQ_MSG_V4_FLAG_TLV NOT to be set for JSON format")
	}
}

func TestNewZmqHeaderV3_Flags_PBUF(t *testing.T) {
	d := newTestDriver(PBUF, false, 0)
	h := d.newZmqHeaderV3(100, 100)
	if h.flags != 0 {
		t.Errorf("expected flags=0 for PBUF without compression, got 0x%02x", h.flags)
	}
}

func TestNewZmqHeaderV3_Version(t *testing.T) {
	d := newTestDriver(TLV, false, 7)
	h := d.newZmqHeaderV3(256, 256)
	if h.version != ZMQ_MSG_VERSION_4 {
		t.Errorf("expected version %d, got %d", ZMQ_MSG_VERSION_4, h.version)
	}
	if h.source_id != 7 {
		t.Errorf("expected source_id=7, got %d", h.source_id)
	}
}

func TestNewZmqHeaderV3_Sizes(t *testing.T) {
	d := newTestDriver(JSON, true, 0)
	h := d.newZmqHeaderV3(1000, 300)
	if h.uncompressed_size != 1000 {
		t.Errorf("expected uncompressed_size=1000, got %d", h.uncompressed_size)
	}
	if h.compressed_size != 300 {
		t.Errorf("expected compressed_size=300, got %d", h.compressed_size)
	}
}

func TestNewZmqHeaderV3_MsgIdIncrement(t *testing.T) {
	d := newTestDriver(TLV, false, 0)
	d.messageId = 5
	h1 := d.newZmqHeaderV3(100, 100)
	h2 := d.newZmqHeaderV3(100, 100)
	if h1.msg_id != 5 {
		t.Errorf("expected first msg_id=5, got %d", h1.msg_id)
	}
	if h2.msg_id != 6 {
		t.Errorf("expected second msg_id=6, got %d", h2.msg_id)
	}
	if d.messageId != 7 {
		t.Errorf("expected d.messageId=7 after two calls, got %d", d.messageId)
	}
}

func TestNewZmqHeaderV3_MsgIdWrap(t *testing.T) {
	d := newTestDriver(TLV, false, 0)
	d.messageId = maxMessageId
	// The wrap check happens in Send(), not in newZmqHeaderV3 itself.
	// newZmqHeaderV3 just increments; the Send() logic resets. We test that
	// incrementing past maxMessageId will eventually reach the sentinel.
	_ = d.newZmqHeaderV3(100, 100)
	if d.messageId != maxMessageId+1 {
		t.Errorf("expected messageId=%d, got %d", maxMessageId+1, d.messageId)
	}
}

// --- compressJSON ---

func TestCompressJSON_RoundTrip(t *testing.T) {
	original := []byte(`{"src":"10.0.0.1","dst":"192.168.1.1","bytes":1000}`)
	compressed, err := compressJSON(original)
	if err != nil {
		t.Fatalf("compressJSON error: %v", err)
	}
	if len(compressed) == 0 {
		t.Fatal("expected non-empty compressed output")
	}

	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib.NewReader error: %v", err)
	}
	defer func() { _ = r.Close() }()
	decompressed, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Errorf("round-trip failed: got %q, want %q", decompressed, original)
	}
}

func TestCompressJSON_EmptyInput(t *testing.T) {
	compressed, err := compressJSON([]byte{})
	if err != nil {
		t.Fatalf("unexpected error on empty input: %v", err)
	}
	// zlib produces a non-empty header even for empty input
	if len(compressed) == 0 {
		t.Error("expected zlib header bytes even for empty input")
	}
}

// --- ZmqDriver.Prepare and Close ---

func TestZmqDriver_Prepare(t *testing.T) {
	d := newTestDriver(TLV, false, 0)
	if err := d.Prepare(); err != nil {
		t.Errorf("Prepare() returned error: %v", err)
	}
}

func TestZmqDriver_Close(t *testing.T) {
	d := newTestDriver(TLV, false, 0)
	if err := d.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

// --- RegisterZmq ---

func TestRegisterZmq(t *testing.T) {
	// RegisterZmq creates a ZmqDriver and registers it with goflow2's transport
	// registry. We just verify it doesn't panic.
	RegisterZmq("tcp://127.0.0.1:15600", TLV, 1, false)
}

// --- ZMQ integration tests (require actual ZMQ socket) ---

const testZmqAddr = "tcp://127.0.0.1:15559"

// TestZmqDriver_InitAndSend tests the full Init() and Send() path.
// Skipped in short mode since it requires binding a real ZMQ socket and sleeps 1s.
func TestZmqDriver_InitAndSend(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}

	d := &ZmqDriver{
		listenAddress: testZmqAddr,
		sourceId:      42,
		msgType:       TLV,
		compress:      false,
		lock:          &sync.RWMutex{},
	}

	// Start subscriber before publisher so it connects during the Init sleep.
	subCtx, err := zmq.NewContext()
	if err != nil {
		t.Fatalf("failed to create ZMQ context: %v", err)
	}
	sub, err := subCtx.NewSocket(zmq.SUB)
	if err != nil {
		t.Fatalf("failed to create SUB socket: %v", err)
	}
	defer func() { _ = sub.Close() }()
	if err := sub.Connect(testZmqAddr); err != nil {
		t.Fatalf("failed to connect subscriber: %v", err)
	}
	// Subscribe to all messages
	if err := sub.SetSubscribe(""); err != nil {
		t.Fatalf("SetSubscribe error: %v", err)
	}

	// Init binds the PUB socket and sleeps 1 second for subscriber connections.
	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	// Send a test TLV payload.
	testPayload := []byte{0x01, 0x01, 0x01} // minimal TLV record (magic + end-of-record)
	if err := d.Send(nil, testPayload); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Receive both frames of the multi-part message (header + payload).
	if err := sub.SetRcvtimeo(2 * time.Second); err != nil {
		t.Fatalf("SetRcvtimeo error: %v", err)
	}
	header, err := sub.RecvBytes(0)
	if err != nil {
		t.Fatalf("failed to receive header frame: %v", err)
	}
	if len(header) == 0 {
		t.Error("received empty header frame")
	}

	payload, err := sub.RecvBytes(0)
	if err != nil {
		t.Fatalf("failed to receive payload frame: %v", err)
	}
	if !bytes.Equal(payload, testPayload) {
		t.Errorf("payload mismatch: got %v, want %v", payload, testPayload)
	}
}

// TestZmqDriver_Send_FirstMessage tests the "first message" logging branch.
func TestZmqDriver_Send_MessageIdLogging(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}

	const addr = "tcp://127.0.0.1:15560"
	d := &ZmqDriver{
		listenAddress: addr,
		sourceId:      1,
		msgType:       JSON,
		compress:      false,
		lock:          &sync.RWMutex{},
		messageId:     1, // triggers "Sending first ZMQ message" log line
	}

	subCtx, _ := zmq.NewContext()
	sub, _ := subCtx.NewSocket(zmq.SUB)
	defer func() { _ = sub.Close() }()
	if err := sub.Connect(addr); err != nil {
		t.Fatalf("failed to connect subscriber: %v", err)
	}
	if err := sub.SetSubscribe(""); err != nil {
		t.Fatalf("SetSubscribe error: %v", err)
	}

	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	// Send with messageId=1 (first message log path)
	if err := d.Send(nil, []byte("hello")); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Now set messageId to a multiple of 1000 to trigger the debug log path
	d.messageId = 1000
	if err := d.Send(nil, []byte("hello")); err != nil {
		t.Fatalf("Send() second error: %v", err)
	}
}

// TestZmqDriver_Send_PBUF tests the PBUF format path in Send().
func TestZmqDriver_Send_PBUF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}

	const addr = "tcp://127.0.0.1:15562"
	d := &ZmqDriver{
		listenAddress: addr,
		sourceId:      1,
		msgType:       PBUF,
		compress:      false,
		lock:          &sync.RWMutex{},
	}

	subCtx, _ := zmq.NewContext()
	sub, _ := subCtx.NewSocket(zmq.SUB)
	defer func() { _ = sub.Close() }()
	if err := sub.Connect(addr); err != nil {
		t.Fatalf("failed to connect subscriber: %v", err)
	}
	if err := sub.SetSubscribe(""); err != nil {
		t.Fatalf("SetSubscribe error: %v", err)
	}
	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	if err := d.Send(nil, []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatalf("Send() PBUF error: %v", err)
	}
}

// TestZmqDriver_Send_MsgIdWrap tests that the messageId wrap-around is triggered in Send().
func TestZmqDriver_Send_MsgIdWrap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}

	const addr = "tcp://127.0.0.1:15563"
	d := &ZmqDriver{
		listenAddress: addr,
		sourceId:      1,
		msgType:       TLV,
		compress:      false,
		lock:          &sync.RWMutex{},
		messageId:     maxMessageId, // triggers wrap-around log in Send()
	}

	subCtx, _ := zmq.NewContext()
	sub, _ := subCtx.NewSocket(zmq.SUB)
	defer func() { _ = sub.Close() }()
	if err := sub.Connect(addr); err != nil {
		t.Fatalf("failed to connect subscriber: %v", err)
	}
	if err := sub.SetSubscribe(""); err != nil {
		t.Fatalf("SetSubscribe error: %v", err)
	}
	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	if err := d.Send(nil, []byte{0x01, 0x01, 0x01}); err != nil {
		t.Fatalf("Send() wrap error: %v", err)
	}
	if d.messageId != 2 {
		t.Errorf("expected messageId to wrap to 2, got %d", d.messageId)
	}
}

// TestZmqDriver_Send_Compressed tests JSON compression in Send().
func TestZmqDriver_Send_Compressed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}

	const addr = "tcp://127.0.0.1:15561"
	d := &ZmqDriver{
		listenAddress: addr,
		sourceId:      1,
		msgType:       JSON,
		compress:      true, // enables zlib compression
		lock:          &sync.RWMutex{},
	}

	subCtx, _ := zmq.NewContext()
	sub, _ := subCtx.NewSocket(zmq.SUB)
	defer func() { _ = sub.Close() }()
	if err := sub.Connect(addr); err != nil {
		t.Fatalf("failed to connect subscriber: %v", err)
	}
	if err := sub.SetSubscribe(""); err != nil {
		t.Fatalf("SetSubscribe error: %v", err)
	}

	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	testData := []byte(`{"src":"10.0.0.1","bytes":1000}`)
	if err := d.Send(nil, testData); err != nil {
		t.Fatalf("Send() compressed error: %v", err)
	}

	if err := sub.SetRcvtimeo(2 * time.Second); err != nil {
		t.Fatalf("SetRcvtimeo error: %v", err)
	}
	// Receive header (skip)
	_, _ = sub.RecvBytes(0)
	// Receive compressed payload
	compressed, err := sub.RecvBytes(0)
	if err != nil {
		t.Fatalf("failed to receive compressed payload: %v", err)
	}
	// Verify it's valid zlib by decompressing it
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib.NewReader error: %v", err)
	}
	decompressed, err := io.ReadAll(r)
	if err := r.Close(); err != nil {
		t.Fatalf("zlib close error: %v", err)
	}
	if err != nil {
		t.Fatalf("decompression error: %v", err)
	}
	if !bytes.Equal(decompressed, testData) {
		t.Errorf("round-trip mismatch: got %q, want %q", decompressed, testData)
	}
}

// TestZmqDriver_Send_UnknownMsgType covers the default case in Send()'s logging switch.
func TestZmqDriver_Send_UnknownMsgType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ZMQ integration test in short mode")
	}

	const addr = "tcp://127.0.0.1:15564"
	d := &ZmqDriver{
		listenAddress: addr,
		sourceId:      1,
		msgType:       MsgFormat(99), // not PBUF/JSON/TLV → hits default case in Send()
		compress:      false,
		lock:          &sync.RWMutex{},
	}

	subCtx, _ := zmq.NewContext()
	sub, _ := subCtx.NewSocket(zmq.SUB)
	defer func() { _ = sub.Close() }()
	if err := sub.Connect(addr); err != nil {
		t.Fatalf("failed to connect subscriber: %v", err)
	}
	if err := sub.SetSubscribe(""); err != nil {
		t.Fatalf("SetSubscribe error: %v", err)
	}
	if err := d.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	// Send should succeed even for unknown type (data is transmitted, default case just logs)
	if err := d.Send(nil, []byte("test")); err != nil {
		t.Fatalf("Send() with unknown msgType error: %v", err)
	}
}
