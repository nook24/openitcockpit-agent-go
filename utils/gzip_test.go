package utils

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
)

func TestAcceptsGzip(t *testing.T) {
	for value, expected := range map[string]bool{
		"":                  false,
		"gzip":              true,
		"GZIP":              true,
		"deflate, gzip":     true,
		"gzip;q=1.0":        true,
		"gzip;q=0":          false,
		"gzip; q=0.0":       false,
		"identity":          false,
		"x-gzip":            true,
		"br, gzip ;q=0.5":   true,
		"gzipper, deflated": false,
	} {
		header := http.Header{}
		if value != "" {
			header.Set("Accept-Encoding", value)
		}
		if actual := AcceptsGzip(header); actual != expected {
			t.Errorf("%q: expected %t, got %t", value, expected, actual)
		}
	}
}

func TestGzip(t *testing.T) {
	data := bytes.Repeat([]byte(`{"name":"value"}`), 100)
	compressed, err := Gzip(data)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(decompressed, data) || len(compressed) >= len(data) {
		t.Errorf("unexpected result: %d bytes compressed, %d bytes decompressed (%v)", len(compressed), len(decompressed), err)
	}
}
