package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// The test generates traffic on the loopback interface instead of relying on internet access or traffic of the system
func TestChecksCheckNetIO(t *testing.T) {
	check := &CheckNetIo{}
	first := runNetIoCheck(t, check)
	if len(first) == 0 {
		t.Fatal("no network interfaces found")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 64*1024))
	}))
	defer server.Close()
	for i := 0; i < 10; i++ {
		response, err := http.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}

	// The rates are calculated in seconds
	time.Sleep(1100 * time.Millisecond)
	second := runNetIoCheck(t, check)

	for name, result := range second {
		if result.Name != name {
			t.Errorf("interface %s: unexpected name %q", name, result.Name)
		}
		previous, ok := first[name]
		if !ok {
			continue
		}
		// The counters of the operating system never decrease
		if result.PacketsSent < previous.PacketsSent || result.BytesReceived < previous.BytesReceived {
			t.Errorf("interface %s: counters decreased: packets sent %d -> %d, bytes received %d -> %d",
				name, previous.PacketsSent, result.PacketsSent, previous.BytesReceived, result.BytesReceived)
		}
	}

	// The traffic of the test server must be visible on the loopback interface (Windows does not report it)
	if runtime.GOOS != "windows" {
		for _, loopback := range []string{"lo", "lo0"} {
			before, ok1 := first[loopback]
			after, ok2 := second[loopback]
			if ok1 && ok2 && after.BytesReceived < before.BytesReceived+10*64*1024 {
				t.Errorf("expected at least %d bytes on %s, got %d", 10*64*1024, loopback, after.BytesReceived-before.BytesReceived)
			}
		}
	}
}

func runNetIoCheck(t *testing.T, check *CheckNetIo) map[string]*resultNetIo {
	t.Helper()
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results, ok := cr.(map[string]*resultNetIo)
	if !ok {
		t.Fatalf("unexpected result type %T", cr)
	}
	return results
}
