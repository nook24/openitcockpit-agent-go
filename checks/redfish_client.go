package checks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const (
	// Maximum size of a single response of a BMC
	redfishMaxResponseSize = 8 * 1024 * 1024
	// Maximum number of pages of a collection (Members@odata.nextLink)
	redfishMaxPages = 20
	// Maximum number of members of a collection which are requested one by one, if $expand is not supported
	redfishMaxResolve  = 200
	redfishServiceRoot = "/redfish/v1"
)

var errRedfishUnauthorized = errors.New("unauthorized")

// redfishClient sends the requests to a BMC. The requests are sent one after another, as BMCs often handle parallel requests badly.
// The session is reused for all collections, so the BMC does not log a new login every few minutes.
type redfishClient struct {
	def        *config.RedfishDefinition
	httpClient *http.Client

	token      string // X-Auth-Token of the session
	sessionURI string
	basicAuth  bool // The BMC has no session service, so every request uses basic authentication
	verified   bool // The credentials for basic authentication were verified
	expand     bool // The BMC supports $expand=.($levels=1)
	requests   int  // Number of requests of the current collection
	warnings   []string
}

// Subset of the service root /redfish/v1
type redfishServiceRootJSON struct {
	RedfishVersion string    `json:"RedfishVersion"`
	Vendor         string    `json:"Vendor"`
	Product        string    `json:"Product"`
	Systems        odataLink `json:"Systems"`
	Chassis        odataLink `json:"Chassis"`
	Managers       odataLink `json:"Managers"`
	SessionService odataLink `json:"SessionService"`
	Links          struct {
		Sessions odataLink `json:"Sessions"`
	} `json:"Links"`
	ProtocolFeaturesSupported struct {
		ExpandQuery struct {
			Levels  bool `json:"Levels"`
			NoLinks bool `json:"NoLinks"`
		} `json:"ExpandQuery"`
	} `json:"ProtocolFeaturesSupported"`
}

type odataLink struct {
	ID string `json:"@odata.id"`
}

// Collection of resources, the members are links or (with $expand) the resources itself
type redfishCollectionJSON struct {
	Members  []json.RawMessage `json:"Members"`
	NextLink string            `json:"Members@odata.nextLink"`
	// Not defined by Redfish, but used by some implementations
	ODataNextLink string `json:"@odata.nextLink"`
}

func newRedfishClient(def *config.RedfishDefinition) *redfishClient {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: def.SkipVerify, // #nosec G402 BMCs use self signed certificates
	}
	if len(def.FingerprintBytes) > 0 {
		// The certificate is accepted if its fingerprint matches, even if it is self signed
		expected := def.FingerprintBytes
		tlsConfig.InsecureSkipVerify = true // #nosec G402 replaced by VerifyPeerCertificate
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("the BMC did not send a certificate")
			}
			fingerprint := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(fingerprint[:], expected) != 1 {
				return fmt.Errorf("the fingerprint of the certificate %s does not match the configured fingerprint", hex.EncodeToString(fingerprint[:]))
			}
			return nil
		}
	}

	transport := &http.Transport{
		// No proxy from the environment, as BMCs are usually in a management network
		Proxy:               nil,
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
	}
	if def.Proxy != "" {
		if proxyURL, err := url.Parse(def.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &redfishClient{
		def: def,
		httpClient: &http.Client{
			Transport: transport,
			// Redfish services do not redirect, a redirect could send the credentials to another host
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// do sends a request with the authentication of the client
func (c *redfishClient) do(ctx context.Context, method, path string, body []byte, auth bool) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.def.Timeout)*time.Second)

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.def.URL+path, reader)
	if err != nil {
		cancel()
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("OData-Version", "4.0")
	request.Header.Set("User-Agent", "openITCOCKPIT-Agent/"+config.AgentVersion)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if auth {
		if c.token != "" {
			request.Header.Set("X-Auth-Token", c.token)
		} else if c.basicAuth && c.def.Username != "" {
			request.SetBasicAuth(c.def.Username, c.def.Password)
		}
	}

	c.requests++
	response, err := c.httpClient.Do(request)
	if err != nil {
		cancel()
		return nil, redfishErrorMessage(err)
	}
	// The context gets canceled when the body is closed
	response.Body = &cancelOnClose{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// getJSON requests a resource and decodes the response. If the session expired, the client logs in again.
func (c *redfishClient) getJSON(ctx context.Context, path string, target interface{}) error {
	err := c.getJSONOnce(ctx, path, target)
	if errors.Is(err, errRedfishUnauthorized) && c.token != "" {
		// The session expired or was deleted on the BMC
		c.token, c.sessionURI = "", ""
		if err := c.login(ctx); err != nil {
			return err
		}
		err = c.getJSONOnce(ctx, path, target)
	}
	if errors.Is(err, errRedfishUnauthorized) {
		return fmt.Errorf("GET %s: unauthorized, please check username and password", path)
	}
	return err
}

func (c *redfishClient) getJSONOnce(ctx context.Context, path string, target interface{}) error {
	response, err := c.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return fmt.Errorf("GET %s: %s", path, err)
	}
	defer response.Body.Close()

	data, err := readRedfishBody(response.Body)
	if err != nil {
		return fmt.Errorf("GET %s: %s", path, err)
	}
	if response.StatusCode == http.StatusUnauthorized {
		return errRedfishUnauthorized
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s%s", path, response.Status, redfishExtendedError(data))
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("GET %s: invalid JSON: %s", path, err)
	}
	return nil
}

func readRedfishBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, redfishMaxResponseSize+1))
	if err != nil {
		return nil, redfishErrorMessage(err)
	}
	if len(data) > redfishMaxResponseSize {
		return nil, fmt.Errorf("response is larger than %d bytes", redfishMaxResponseSize)
	}
	return data, nil
}

// redfishExtendedError returns the message of a Redfish error response, e.g. ": The resource was not found"
func redfishExtendedError(data []byte) string {
	var redfishError struct {
		Error struct {
			Message      string `json:"message"`
			ExtendedInfo []struct {
				Message string `json:"Message"`
			} `json:"@Message.ExtendedInfo"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &redfishError) != nil {
		return ""
	}
	if len(redfishError.Error.ExtendedInfo) > 0 && redfishError.Error.ExtendedInfo[0].Message != "" {
		return ": " + redfishError.Error.ExtendedInfo[0].Message
	}
	if redfishError.Error.Message != "" {
		return ": " + redfishError.Error.Message
	}
	return ""
}

func redfishErrorMessage(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		err = urlError.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timeout, the BMC did not answer in time")
	}
	return err
}

// connect reads the service root and logs in, if the client has no session yet
func (c *redfishClient) connect(ctx context.Context) (*redfishServiceRootJSON, error) {
	// The service root does not require authentication, but some BMCs require it anyway
	root := &redfishServiceRootJSON{}
	err := c.getJSONOnce(ctx, redfishServiceRoot, root)
	unauthorized := errors.Is(err, errRedfishUnauthorized)
	if err != nil && !unauthorized {
		return nil, err
	}

	if c.token == "" && !c.basicAuth {
		c.sessionURI = root.Links.Sessions.ID
		if err := c.login(ctx); err != nil {
			return nil, err
		}
	}
	if unauthorized {
		root = &redfishServiceRootJSON{}
		if err := c.getJSON(ctx, redfishServiceRoot, root); err != nil {
			return nil, err
		}
	}
	// With basic authentication, wrong credentials would only be noticed by the single resources
	if c.basicAuth && !c.verified && c.def.Username != "" && root.Systems.ID != "" {
		var systems json.RawMessage
		if err := c.getJSON(ctx, root.Systems.ID, &systems); err != nil {
			return nil, err
		}
		c.verified = true
	}

	expand := root.ProtocolFeaturesSupported.ExpandQuery
	c.expand = expand.Levels && expand.NoLinks
	return root, nil
}

// login creates a session. If the BMC has no session service, basic authentication is used.
func (c *redfishClient) login(ctx context.Context) error {
	if c.def.Username == "" {
		// No authentication, e.g. a Redfish mockup server
		c.basicAuth = true
		return nil
	}

	sessions := c.sessionURI
	if sessions == "" {
		sessions = redfishServiceRoot + "/SessionService/Sessions"
	}
	body, _ := json.Marshal(map[string]string{"UserName": c.def.Username, "Password": c.def.Password})
	response, err := c.do(ctx, http.MethodPost, sessions, body, false)
	if err != nil {
		return fmt.Errorf("login: %s", err)
	}
	defer response.Body.Close()
	data, _ := readRedfishBody(response.Body)

	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return fmt.Errorf("login failed: %s, please check username and password%s", response.Status, redfishExtendedError(data))
	case response.StatusCode >= 200 && response.StatusCode < 300 && response.Header.Get("X-Auth-Token") != "":
		c.token = response.Header.Get("X-Auth-Token")
		c.basicAuth = false
		c.sessionURI = redfishSessionURI(response.Header.Get("Location"), data)
		return nil
	default:
		// No session service (e.g. 404 or 405), so basic authentication is used for every request
		c.token, c.sessionURI = "", ""
		c.basicAuth = true
		return nil
	}
}

// redfishSessionURI returns the path of the created session, which is required to delete it
func redfishSessionURI(location string, body []byte) string {
	if location != "" {
		if parsed, err := url.Parse(location); err == nil && parsed.Path != "" {
			return parsed.Path
		}
	}
	var session odataLink
	if json.Unmarshal(body, &session) == nil {
		return session.ID
	}
	return ""
}

// logout deletes the session on the BMC, so it does not have to wait for the session timeout
func (c *redfishClient) logout() {
	if c.token == "" || c.sessionURI == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if response, err := c.do(ctx, http.MethodDelete, c.sessionURI, nil, true); err == nil {
		_ = response.Body.Close()
	}
	c.token, c.sessionURI = "", ""
}

// members returns all members of a collection. Members which are only links get requested one by one.
func (c *redfishClient) members(ctx context.Context, path string) ([]json.RawMessage, error) {
	var members []json.RawMessage
	next := c.expandPath(path)
	visited := map[string]bool{}
	for page := 0; next != "" && !visited[next] && page < redfishMaxPages; page++ {
		visited[next] = true
		var collection redfishCollectionJSON
		if err := c.getJSON(ctx, next, &collection); err != nil {
			if page == 0 {
				return nil, err
			}
			// Keep the members of the previous pages
			c.warnings = append(c.warnings, err.Error())
			break
		}
		members = append(members, collection.Members...)
		next = collection.NextLink
		if next == "" {
			next = collection.ODataNextLink
		}
	}
	members = uniqueRedfishMembers(members)

	// Only members which are links have to be requested, members which are already expanded do not count
	resolved := make([]json.RawMessage, 0, len(members))
	requests := 0
	for _, member := range members {
		if isRedfishLink(member) {
			if requests >= redfishMaxResolve {
				c.warnings = append(c.warnings, fmt.Sprintf("%s: only the first %d of %d members were requested", path, redfishMaxResolve, len(members)))
				break
			}
			requests++
		}
		resource, err := c.resolve(ctx, member)
		if err != nil {
			// A single member which can not be read should not hide the other members
			c.warnings = append(c.warnings, err.Error())
			continue
		}
		resolved = append(resolved, resource)
	}
	return resolved, nil
}

// uniqueRedfishMembers removes duplicate members, e.g. if a service ignores the $skiptoken of the next link
func uniqueRedfishMembers(members []json.RawMessage) []json.RawMessage {
	seen := make(map[string]bool, len(members))
	unique := make([]json.RawMessage, 0, len(members))
	for _, member := range members {
		var link odataLink
		if json.Unmarshal(member, &link) == nil && link.ID != "" {
			if seen[link.ID] {
				continue
			}
			seen[link.ID] = true
		}
		unique = append(unique, member)
	}
	return unique
}

// isRedfishLink returns true if the JSON is only a link like {"@odata.id": "/redfish/v1/Systems/1"}
func isRedfishLink(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return false
	}
	_, ok := object["@odata.id"]
	return ok && len(object) == 1
}

// resolve requests a resource if the given JSON is only a link like {"@odata.id": "/redfish/v1/Systems/1"}
func (c *redfishClient) resolve(ctx context.Context, data json.RawMessage) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	link, ok := object["@odata.id"]
	if !ok || len(object) > 1 {
		return data, nil
	}
	var path string
	if err := json.Unmarshal(link, &path); err != nil {
		return nil, err
	}
	var resource json.RawMessage
	err := c.getJSON(ctx, redfishPath(path), &resource)
	return resource, err
}

// expandPath adds $expand to the path of a collection, if the BMC supports it
func (c *redfishClient) expandPath(path string) string {
	if !c.expand || strings.Contains(path, "$expand") {
		return path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "$expand=.($levels=1)"
}

// redfishPath removes the fragment of a link, e.g. /redfish/v1/Chassis/1/Thermal#/Fans/0
func redfishPath(path string) string {
	if index := strings.Index(path, "#"); index >= 0 {
		return path[:index]
	}
	return path
}
