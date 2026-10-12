package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

func newHTTPDefinition(t *testing.T, name, url string, modify func(d *config.HTTPDefinition)) *config.HTTPDefinition {
	t.Helper()
	followRedirects := true
	d := &config.HTTPDefinition{
		Name:                 name,
		URL:                  url,
		Method:               "GET",
		Timeout:              5,
		ExpectedStatus:       "200-399",
		ExpectedStatusRanges: [][2]int{{200, 399}},
		FollowRedirects:      &followRedirects,
	}
	if modify != nil {
		modify(d)
	}
	return d
}

func runHTTPCheck(t *testing.T, definitions ...*config.HTTPDefinition) map[string]*resultHTTP {
	t.Helper()
	c := &CheckHTTP{}
	if enabled, _ := c.Configure(&config.Configuration{HTTPConfiguration: definitions}); !enabled {
		t.Fatal("check should be enabled")
	}
	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	results := map[string]*resultHTTP{}
	for name, res := range r.(map[string]interface{}) {
		if httpResult, ok := res.(*resultHTTP); ok {
			results[name] = httpResult
		}
	}
	return results
}

func TestCheckHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "status: healthy")
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "database down", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); !ok || user != "admin" || password != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "welcome")
	})
	mux.HandleFunc("/vhost", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "host="+r.Host+" agent="+r.UserAgent())
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	noRedirects := false
	results := runHTTPCheck(t,
		newHTTPDefinition(t, "ok", server.URL+"/ok", func(d *config.HTTPDefinition) {
			d.MatchRegexp = regexp.MustCompile(`healthy`)
		}),
		newHTTPDefinition(t, "nomatch", server.URL+"/ok", func(d *config.HTTPDefinition) {
			d.MatchRegexp = regexp.MustCompile(`degraded`)
		}),
		newHTTPDefinition(t, "error", server.URL+"/error", nil),
		newHTTPDefinition(t, "error_expected", server.URL+"/error", func(d *config.HTTPDefinition) {
			d.ExpectedStatus = "503"
			d.ExpectedStatusRanges = [][2]int{{503, 503}}
		}),
		newHTTPDefinition(t, "redirect", server.URL+"/redirect", nil),
		newHTTPDefinition(t, "redirect_not_followed", server.URL+"/redirect", func(d *config.HTTPDefinition) {
			d.FollowRedirects = &noRedirects
		}),
		newHTTPDefinition(t, "auth", server.URL+"/auth", func(d *config.HTTPDefinition) {
			d.Username, d.Password = "admin", "secret"
		}),
		newHTTPDefinition(t, "auth_missing", server.URL+"/auth", nil),
		newHTTPDefinition(t, "vhost", server.URL+"/vhost", func(d *config.HTTPDefinition) {
			d.HostHeader = "intranet.example.com"
			d.MatchRegexp = regexp.MustCompile(`host=intranet\.example\.com agent=openITCOCKPIT-Agent/`)
		}),
		newHTTPDefinition(t, "timeout", server.URL+"/slow", func(d *config.HTTPDefinition) {
			d.Timeout = 1
		}),
		newHTTPDefinition(t, "head", server.URL+"/ok", func(d *config.HTTPDefinition) {
			d.Method = "HEAD"
		}),
	)

	expect := func(name string, statusCode int, statusOK bool) *resultHTTP {
		t.Helper()
		res, ok := results[name]
		if !ok {
			t.Fatalf("missing result for %s", name)
		}
		if res.StatusCode != statusCode || res.StatusOK != statusOK {
			t.Errorf("%s: expected status %d (ok=%v): %+v", name, statusCode, statusOK, res)
		}
		return res
	}

	if res := expect("ok", 200, true); res.ContentMatch == nil || !*res.ContentMatch || res.BodySize != 15 || res.ResponseTime <= 0 {
		t.Errorf("unexpected result: %+v", res)
	}
	if res := expect("nomatch", 200, true); res.ContentMatch == nil || *res.ContentMatch {
		t.Errorf("content must not match: %+v", res)
	}
	if res := expect("error", 503, false); res.ConnectionError != "" || res.ContentMatch != nil {
		t.Errorf("unexpected result: %+v", res)
	}
	expect("error_expected", 503, true)
	if res := expect("redirect", 200, true); res.Redirects != 1 || res.FinalURL != server.URL+"/ok" {
		t.Errorf("redirect should be followed: %+v", res)
	}
	if res := expect("redirect_not_followed", 302, true); res.Redirects != 0 {
		t.Errorf("redirect must not be followed: %+v", res)
	}
	expect("auth", 200, true)
	expect("auth_missing", 401, false)
	if res := expect("vhost", 200, true); !*res.ContentMatch {
		t.Errorf("host header or user agent not sent: %+v", res)
	}
	if res := expect("timeout", 0, false); res.ConnectionError != "timeout" {
		t.Errorf("expected timeout: %+v", res)
	}
	if res := expect("head", 200, true); res.BodySize != 0 {
		t.Errorf("HEAD must not return a body: %+v", res)
	}
}

func TestCheckHTTPConnectionErrors(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer tlsServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + listener.Addr().String() + "/"
	listener.Close()

	results := runHTTPCheck(t,
		newHTTPDefinition(t, "refused", closed, nil),
		newHTTPDefinition(t, "untrusted", tlsServer.URL, nil),
		newHTTPDefinition(t, "skip_verify", tlsServer.URL, func(d *config.HTTPDefinition) {
			d.SkipVerify = true
		}),
		&config.HTTPDefinition{Name: "invalid", ConfigError: "invalid url"},
	)

	if res := results["refused"]; res.StatusCode != 0 || !strings.Contains(res.ConnectionError, "refused") {
		t.Errorf("expected connection refused: %+v", res)
	}
	if res := results["untrusted"]; res.StatusCode != 0 || !strings.Contains(res.ConnectionError, "certificate") {
		t.Errorf("expected certificate error: %+v", res)
	}
	if res := results["skip_verify"]; res.StatusCode != 200 || !res.StatusOK {
		t.Errorf("expected 200 with skip_verify: %+v", res)
	}
	if _, ok := results["invalid"]; ok {
		t.Error("invalid definition must be reported as error")
	}
}
