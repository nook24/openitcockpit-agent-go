package checks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const (
	// Only this amount of the response body is read to search for the match regex
	httpMaxBodyBytes = 1024 * 1024
	// Number of HTTP requests running at the same time
	httpMaxParallelRequests = 8
	httpMaxRedirects        = 10
)

// CheckHTTP monitors HTTP(S) endpoints
type CheckHTTP struct {
	definitions []*config.HTTPDefinition
}

// Name will be used in the response as check name
func (c *CheckHTTP) Name() string {
	return "http"
}

type resultHTTP struct {
	URL             string  `json:"url"`
	Method          string  `json:"method"`
	StatusCode      int     `json:"status_code"`      // 0 if no response was received
	ExpectedStatus  string  `json:"expected_status"`  // e.g.: 200-399
	StatusOK        bool    `json:"status_ok"`        // status_code matches expected_status
	ResponseTime    float64 `json:"response_time"`    // Seconds until the response body was read
	BodySize        int64   `json:"body_size"`        // Bytes (max. 1 MiB are read)
	ContentMatch    *bool   `json:"content_match"`    // null if no match regex is configured
	FinalURL        string  `json:"final_url"`        // URL after all redirects
	Redirects       int     `json:"redirects"`        // Number of followed redirects
	ConnectionError string  `json:"connection_error"` // e.g. connection refused, timeout or TLS errors
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckHTTP) Run(ctx context.Context) (interface{}, error) {
	result := make(map[string]interface{}, len(c.definitions))
	var mutex sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, httpMaxParallelRequests)

	for _, definition := range c.definitions {
		if definition.ConfigError != "" {
			mutex.Lock()
			result[definition.Name] = map[string]string{"error": definition.ConfigError}
			mutex.Unlock()
			continue
		}

		wg.Add(1)
		go func(d *config.HTTPDefinition) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			res := checkHTTPEndpoint(ctx, d)
			mutex.Lock()
			result[d.Name] = res
			mutex.Unlock()
		}(definition)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckHTTP) Configure(cfg *config.Configuration) (bool, error) {
	c.definitions = cfg.HTTPConfiguration
	return len(c.definitions) > 0, nil
}

func checkHTTPEndpoint(ctx context.Context, d *config.HTTPDefinition) *resultHTTP {
	res := &resultHTTP{
		URL:            d.URL,
		Method:         d.Method,
		ExpectedStatus: d.ExpectedStatus,
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.Timeout)*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, d.Method, d.URL, nil)
	if err != nil {
		res.ConnectionError = err.Error()
		return res
	}
	request.Header.Set("User-Agent", "openITCOCKPIT-Agent/"+config.AgentVersion)
	if d.Username != "" {
		request.SetBasicAuth(d.Username, d.Password)
	}
	if d.HostHeader != "" {
		request.Host = d.HostHeader
	}

	transport := &http.Transport{
		// No proxy from the environment, as most endpoints are internal services
		Proxy:             nil,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: d.SkipVerify, // #nosec G402
		},
	}
	if d.Proxy != "" {
		if proxyURL, err := url.Parse(d.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !*d.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) > httpMaxRedirects {
				return fmt.Errorf("stopped after %d redirects", httpMaxRedirects)
			}
			res.Redirects = len(via)
			return nil
		},
	}

	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		res.ResponseTime = time.Since(start).Seconds()
		res.ConnectionError = httpErrorMessage(err)
		return res
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, httpMaxBodyBytes))
	res.ResponseTime = time.Since(start).Seconds()
	if err != nil {
		res.ConnectionError = httpErrorMessage(err)
	}

	res.StatusCode = response.StatusCode
	res.BodySize = int64(len(body))
	res.FinalURL = response.Request.URL.String()
	for _, statusRange := range d.ExpectedStatusRanges {
		if res.StatusCode >= statusRange[0] && res.StatusCode <= statusRange[1] {
			res.StatusOK = true
			break
		}
	}
	if d.MatchRegexp != nil {
		match := d.MatchRegexp.Match(body)
		res.ContentMatch = &match
	}

	return res
}

// httpErrorMessage removes the redundant method and url from errors of the http client
func httpErrorMessage(err error) string {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		if errors.Is(urlError.Err, context.DeadlineExceeded) {
			return "timeout"
		}
		return urlError.Err.Error()
	}
	return err.Error()
}
