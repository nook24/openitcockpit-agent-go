package pushclient

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// fakePushServer records the content encoding of the requests and decodes gzip compressed requests
type fakePushServer struct {
	mutex          sync.Mutex
	acceptEncoding string // Accept-Encoding header of the responses
	rejectGzip     bool   // Answer gzip compressed requests with 415
	encodings      []string
	payloads       []map[string]interface{}
}

func (f *fakePushServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	encoding := r.Header.Get("Content-Encoding")
	f.encodings = append(f.encodings, encoding)
	if f.acceptEncoding != "" {
		w.Header().Set("Accept-Encoding", f.acceptEncoding)
	}
	if encoding == "gzip" && f.rejectGzip {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	var body io.Reader = r.Body
	if encoding == "gzip" {
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body = reader
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.payloads = append(f.payloads, payload)
	_, _ = w.Write([]byte(`{"received_checks": 1}`))
}

func pushTestRequest(t *testing.T, p *PushClient, server *httptest.Server) int {
	t.Helper()
	target, _ := url.Parse(server.URL + "/agentconnector/submit_checkdata.json")
	res := submitCheckDataResponse{}
	status, err := p.httpRequest(context.Background(), target, map[string]string{"agentuuid": "test", "checkdata": "data"}, &res)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func TestPushGzipNegotiation(t *testing.T) {
	fake := &fakePushServer{}
	server := httptest.NewServer(fake)
	defer server.Close()
	p := &PushClient{}

	// An older server without Accept-Encoding header only gets uncompressed requests
	pushTestRequest(t, p, server)
	pushTestRequest(t, p, server)

	// The server announces gzip: the following requests are compressed
	fake.mutex.Lock()
	fake.acceptEncoding = "gzip"
	fake.mutex.Unlock()
	pushTestRequest(t, p, server)
	pushTestRequest(t, p, server)

	// The server does not announce gzip anymore
	fake.mutex.Lock()
	fake.acceptEncoding = ""
	fake.mutex.Unlock()
	pushTestRequest(t, p, server)
	pushTestRequest(t, p, server)

	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	expected := []string{"", "", "", "gzip", "gzip", ""}
	if len(fake.encodings) != len(expected) {
		t.Fatalf("expected %d requests, got %v", len(expected), fake.encodings)
	}
	for i := range expected {
		if fake.encodings[i] != expected[i] {
			t.Errorf("request %d: expected content encoding %q, got %q", i, expected[i], fake.encodings[i])
		}
	}
	// The compressed requests contain the same data
	for i, payload := range fake.payloads {
		if payload["agentuuid"] != "test" || payload["checkdata"] != "data" {
			t.Errorf("request %d: unexpected payload %v", i, payload)
		}
	}
}

func TestPushGzipRejected(t *testing.T) {
	// The server announces gzip, but rejects compressed requests: the request is sent again without compression
	fake := &fakePushServer{acceptEncoding: "gzip", rejectGzip: true}
	server := httptest.NewServer(fake)
	defer server.Close()
	p := &PushClient{gzipRequests: true}

	if status := pushTestRequest(t, p, server); status != http.StatusOK {
		t.Errorf("expected status 200 after the retry, got %d", status)
	}
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if len(fake.encodings) != 2 || fake.encodings[0] != "gzip" || fake.encodings[1] != "" || len(fake.payloads) != 1 {
		t.Errorf("unexpected requests: %v", fake.encodings)
	}
}
