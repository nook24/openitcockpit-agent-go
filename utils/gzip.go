package utils

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
)

// AcceptsGzip returns true if the Accept-Encoding header contains gzip, e.g. "gzip", "gzip, deflate" or "gzip;q=1.0".
// A coding with q=0 is not acceptable. Requests use the header for the response (RFC 9110),
// responses for the content codings the server accepts for requests (RFC 7694).
func AcceptsGzip(header http.Header) bool {
	for _, value := range header.Values("Accept-Encoding") {
		for _, coding := range strings.Split(value, ",") {
			parts := strings.Split(coding, ";")
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name != "gzip" && name != "x-gzip" {
				continue
			}
			acceptable := true
			for _, parameter := range parts[1:] {
				key, quality, found := strings.Cut(strings.TrimSpace(parameter), "=")
				if found && strings.EqualFold(strings.TrimSpace(key), "q") {
					if q, err := strconv.ParseFloat(strings.TrimSpace(quality), 64); err == nil && q == 0 {
						acceptable = false
					}
				}
			}
			if acceptable {
				return true
			}
		}
	}
	return false
}

// Gzip compresses data
func Gzip(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
