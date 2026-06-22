package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	localtransport "github.com/synfinatic/netflow2ng/transport"
	"github.com/sirupsen/logrus"
)

func init() {
	// Initialize the package-level logger so error-path tests don't panic on nil log.
	l := logrus.New()
	l.SetOutput(io.Discard) // suppress log noise in tests
	log = l
}

// --- SourceId.Validate ---

func TestSourceId_Validate_Valid(t *testing.T) {
	cases := []SourceId{0, 1, 128, 255}
	for _, s := range cases {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%d) returned unexpected error: %v", s, err)
		}
	}
}

func TestSourceId_Validate_Invalid(t *testing.T) {
	cases := []SourceId{-1, 256, 1000, -100}
	for _, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("Validate(%d) expected error, got nil", s)
		}
	}
}

// --- Address.Value ---

func TestAddress_Value_Valid(t *testing.T) {
	cases := []struct {
		addr    Address
		wantIP  string
		wantPort int
	}{
		{"0.0.0.0:2055", "0.0.0.0", 2055},
		{"127.0.0.1:9999", "127.0.0.1", 9999},
		{"*:5556", "*", 5556},
	}
	for _, c := range cases {
		ip, port, err := c.addr.Value()
		if err != nil {
			t.Errorf("Value(%q) unexpected error: %v", c.addr, err)
			continue
		}
		if ip != c.wantIP {
			t.Errorf("Value(%q): expected IP %q, got %q", c.addr, c.wantIP, ip)
		}
		if port != c.wantPort {
			t.Errorf("Value(%q): expected port %d, got %d", c.addr, c.wantPort, port)
		}
	}
}

func TestAddress_Value_MissingPort(t *testing.T) {
	a := Address("127.0.0.1")
	_, _, err := a.Value()
	if err == nil {
		t.Error("expected error for address without port, got nil")
	}
}

func TestAddress_Value_InvalidPort(t *testing.T) {
	a := Address("0.0.0.0:notaport")
	_, _, err := a.Value()
	if err == nil {
		t.Error("expected error for non-numeric port, got nil")
	}
}

// TestAddress_Value_HighPorts verifies ports above 32767 are accepted.
// These were incorrectly rejected when ParseInt used bitSize=16 (max int16 = 32767).
func TestAddress_Value_HighPorts(t *testing.T) {
	cases := []struct {
		addr     Address
		wantPort int
	}{
		{"0.0.0.0:32768", 32768},
		{"0.0.0.0:50000", 50000},
		{"0.0.0.0:65535", 65535},
	}
	for _, c := range cases {
		_, port, err := c.addr.Value()
		if err != nil {
			t.Errorf("Value(%q) returned unexpected error: %v (regression: bitSize=16 rejected ports > 32767)", c.addr, err)
			continue
		}
		if port != c.wantPort {
			t.Errorf("Value(%q): expected port %d, got %d", c.addr, c.wantPort, port)
		}
	}
}

// TestAddress_Value_OutOfRangePorts verifies port bounds enforcement (1–65535).
func TestAddress_Value_OutOfRangePorts(t *testing.T) {
	cases := []Address{
		"0.0.0.0:0",     // port 0 not allowed
		"0.0.0.0:65536", // one past max
		"0.0.0.0:-1",    // negative
	}
	for _, a := range cases {
		_, _, err := a.Value()
		if err == nil {
			t.Errorf("Value(%q) expected error for out-of-range port, got nil", a)
		}
	}
}

// --- LoadMappingYaml ---

func TestLoadMappingYaml(t *testing.T) {
	cfg, err := LoadMappingYaml()
	if err != nil {
		t.Fatalf("LoadMappingYaml() returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil ProducerConfig")
	}
}

// --- PrintVersion ---

func TestPrintVersion(t *testing.T) {
	// Capture stdout
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}
	os.Stdout = w

	// Set known values for the version variables.
	Version = "1.2.3"
	CommitID = "abc1234"
	Tag = "v1.2.3"
	Buildinfos = "2024-01-01T00:00:00Z"
	Delta = ""

	PrintVersion()

	if err := w.Close(); err != nil {
		t.Fatalf("pipe close error: %v", err)
	}
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "netflow2ng") {
		t.Errorf("expected 'netflow2ng' in output, got: %q", output)
	}
	if !strings.Contains(output, "1.2.3") {
		t.Errorf("expected version '1.2.3' in output, got: %q", output)
	}
	if !strings.Contains(output, COPYRIGHT_YEAR) {
		t.Errorf("expected copyright year %q in output, got: %q", COPYRIGHT_YEAR, output)
	}
}

func TestPrintVersion_WithDelta(t *testing.T) {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Save and restore version globals
	savedDelta := Delta
	savedTag := Tag
	defer func() {
		Delta = savedDelta
		Tag = savedTag
	}()

	Delta = "5 files"
	Tag = "v1.0.0"
	Version = "1.0.0"

	PrintVersion()

	if err := w.Close(); err != nil {
		t.Fatalf("pipe close error: %v", err)
	}
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "5 files delta") {
		t.Errorf("expected delta info in output, got: %q", output)
	}
	if !strings.Contains(output, fmt.Sprintf("v%s", Version)) {
		t.Errorf("expected version in output, got: %q", output)
	}
}

// --- setupLogging ---

func TestSetupLogging_JSON(t *testing.T) {
	l := logrus.New()
	setupLogging("json", "debug", l)
	if l.Level != logrus.DebugLevel {
		t.Errorf("expected debug level, got %v", l.Level)
	}
}

func TestSetupLogging_Default(t *testing.T) {
	l := logrus.New()
	setupLogging("default", "warn", l)
	if l.Level != logrus.WarnLevel {
		t.Errorf("expected warn level, got %v", l.Level)
	}
}

// --- selectFormat ---

func TestSelectFormat_TLV(t *testing.T) {
	l := logrus.New()
	msgType, f, compress, err := selectFormat("tlv", l)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != localtransport.TLV {
		t.Errorf("expected TLV msgType, got %v", msgType)
	}
	if f == nil {
		t.Error("expected non-nil formatter")
	}
	if compress {
		t.Error("expected compress=false for TLV")
	}
}

func TestSelectFormat_JSON(t *testing.T) {
	l := logrus.New()
	msgType, f, compress, err := selectFormat("json", l)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != localtransport.JSON {
		t.Errorf("expected JSON msgType, got %v", msgType)
	}
	if f == nil {
		t.Error("expected non-nil formatter")
	}
	if compress {
		t.Error("expected compress=false for json")
	}
}

func TestSelectFormat_JCompress(t *testing.T) {
	l := logrus.New()
	msgType, f, compress, err := selectFormat("jcompress", l)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != localtransport.JSON {
		t.Errorf("expected JSON msgType for jcompress, got %v", msgType)
	}
	if f == nil {
		t.Error("expected non-nil formatter")
	}
	if !compress {
		t.Error("expected compress=true for jcompress")
	}
}

// TestSelectFormat_JCompress_SingleLog verifies that "jcompress" emits exactly one
// log line. The bug was a fallthrough to the "json" case that unconditionally logged
// "Using ntopng JSON format for ZMQ", causing two log lines for jcompress.
func TestSelectFormat_JCompress_SingleLog(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	l.SetLevel(logrus.InfoLevel)
	l.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	if _, _, _, err := selectFormat("jcompress", l); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if count := strings.Count(output, "ntopng"); count != 1 {
		t.Errorf("expected exactly 1 log line mentioning ntopng for jcompress, got %d: %q", count, output)
	}
	// jcompress should log the compressed-format message but NOT the plain-JSON message
	if !strings.Contains(output, "compressed") {
		t.Errorf("jcompress log should mention 'compressed'; got: %q", output)
	}
	if strings.Contains(output, "Using ntopng JSON format for ZMQ") {
		t.Errorf("jcompress should not log the plain 'JSON format for ZMQ' message; got: %q", output)
	}
}

// TestSelectFormat_JSON_LogsMessage verifies that "json" format logs exactly the
// "JSON format" message and not the "compressed" one.
func TestSelectFormat_JSON_LogsMessage(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	l.SetLevel(logrus.InfoLevel)
	l.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	if _, _, _, err := selectFormat("json", l); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "JSON format for ZMQ") {
		t.Errorf("json format should log 'JSON format for ZMQ'; got: %q", output)
	}
	if strings.Contains(output, "compressed") {
		t.Errorf("json format should not log anything about compression; got: %q", output)
	}
}

func TestSelectFormat_Proto(t *testing.T) {
	l := logrus.New()
	_, _, _, err := selectFormat("proto", l)
	if err == nil {
		t.Error("expected error for proto format, got nil")
	}
}

func TestSelectFormat_Unknown(t *testing.T) {
	l := logrus.New()
	_, _, _, err := selectFormat("badformat", l)
	if err == nil {
		t.Error("expected error for unknown format, got nil")
	}
}

// --- newHealthHandler ---

func TestNewHealthHandler_NotCollecting(t *testing.T) {
	var collecting atomic.Bool // zero value = false
	handler := newHealthHandler(&collecting)

	req := httptest.NewRequest(http.MethodGet, "/__health", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Not OK") {
		t.Errorf("expected 'Not OK' in body, got %q", rr.Body.String())
	}
}

func TestNewHealthHandler_Collecting(t *testing.T) {
	var collecting atomic.Bool
	collecting.Store(true)
	handler := newHealthHandler(&collecting)

	req := httptest.NewRequest(http.MethodGet, "/__health", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "OK") {
		t.Errorf("expected 'OK' in body, got %q", rr.Body.String())
	}
}

// --- newTemplatesHandler ---

// mockTemplateSource implements templateSource for testing.
type mockTemplateSource struct{}

func (m *mockTemplateSource) GetTemplatesForAllSources() map[string]map[uint64]interface{} {
	return map[string]map[uint64]interface{}{
		"192.168.1.1": {256: "template-data"},
	}
}

func TestNewTemplatesHandler_Success(t *testing.T) {
	ts := &mockTemplateSource{}
	handler := newTemplatesHandler(ts)

	req := httptest.NewRequest(http.MethodGet, "/templates", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "template-data") {
		t.Errorf("expected template data in response, got %q", rr.Body.String())
	}
}

// failWriteRecorder is a ResponseRecorder whose Write always returns an error.
type failWriteRecorder struct {
	*httptest.ResponseRecorder
}

func (f *failWriteRecorder) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write failed")
}

func TestNewHealthHandler_WriteError_NotCollecting(t *testing.T) {
	var collecting atomic.Bool // zero value = false
	handler := newHealthHandler(&collecting)
	req := httptest.NewRequest(http.MethodGet, "/__health", nil)
	rr := &failWriteRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler(rr, req) // Write fails → log.Error path covered
}

func TestNewHealthHandler_WriteError_Collecting(t *testing.T) {
	var collecting atomic.Bool
	collecting.Store(true)
	handler := newHealthHandler(&collecting)
	req := httptest.NewRequest(http.MethodGet, "/__health", nil)
	rr := &failWriteRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler(rr, req) // Write fails → log.Error path covered
}

// unmarshalableTemplateSource returns a map containing a channel, which json.MarshalIndent
// cannot serialize. This triggers the error branch in newTemplatesHandler.
type unmarshalableTemplateSource struct{}

func (u *unmarshalableTemplateSource) GetTemplatesForAllSources() map[string]map[uint64]interface{} {
	return map[string]map[uint64]interface{}{
		"src": {1: make(chan int)}, // channels cannot be JSON-marshaled
	}
}

func TestNewTemplatesHandler_JSONError(t *testing.T) {
	ts := &unmarshalableTemplateSource{}
	handler := newTemplatesHandler(ts)

	req := httptest.NewRequest(http.MethodGet, "/templates", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for JSON marshal error, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Internal Server Error") {
		t.Errorf("expected error body, got %q", rr.Body.String())
	}
}

// TestNewTemplatesHandler_JSONError_WriteError triggers both the JSON error path AND
// the subsequent Write failure, covering the log.Error branch after the 500 write.
func TestNewTemplatesHandler_JSONError_WriteError(t *testing.T) {
	ts := &unmarshalableTemplateSource{}
	handler := newTemplatesHandler(ts)
	req := httptest.NewRequest(http.MethodGet, "/templates", nil)
	rr := &failWriteRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler(rr, req) // marshal fails → wr.Write("Internal Server Error") fails → log.Error path
}

// TestNewTemplatesHandler_SuccessWriteError triggers the Write failure in the success path.
func TestNewTemplatesHandler_SuccessWriteError(t *testing.T) {
	ts := &mockTemplateSource{}
	handler := newTemplatesHandler(ts)
	req := httptest.NewRequest(http.MethodGet, "/templates", nil)
	rr := &failWriteRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler(rr, req) // marshal succeeds → wr.Write(body) fails → log.Error path
}
