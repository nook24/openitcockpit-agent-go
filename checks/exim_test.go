//go:build linux || freebsd
// +build linux freebsd

package checks

import (
	"strings"
	"testing"
)

// Output of "exim -bp"
const testEximQueue = ` 4d  2.1K 1oWbIa-0002Xy-Ad <user@example.com>
          D delivered@example.org
            recipient@example.org

25m   567 1oWbJb-0003Ab-Cd <> *** frozen ***
          root@example.com

 0m  1.5M 1oWbKc-0004Bc-De <reports@example.com>
          boss@example.net

`

func TestParseEximQueue(t *testing.T) {
	result := parseEximQueue(strings.NewReader(testEximQueue))
	if result.Messages != 3 || result.Frozen != 1 {
		t.Errorf("unexpected counts: %+v", result)
	}
	if result.OldestAge != 4*86400 {
		t.Errorf("unexpected oldest age: %d", result.OldestAge)
	}
	expectedSize := int64(2150) + 567 + int64(1572864) // 2.1K, 567 and 1.5M
	if result.SizeBytes != expectedSize {
		t.Errorf("unexpected size: %d, expected %d", result.SizeBytes, expectedSize)
	}

	if empty := parseEximQueue(strings.NewReader("")); empty.Messages != 0 || empty.OldestAge != 0 {
		t.Errorf("unexpected result for an empty queue: %+v", empty)
	}
}
