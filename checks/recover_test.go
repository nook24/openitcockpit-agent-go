package checks

import (
	"errors"
	"strings"
	"testing"
)

func TestProtect(t *testing.T) {
	result, err := protect("test", func() (*int, error) {
		var values []int
		_ = values[3] // index out of range
		return nil, nil
	})
	var panicErr *panicError
	if result != nil || !errors.As(err, &panicErr) || !strings.Contains(err.Error(), "test: internal error") {
		t.Errorf("expected a recovered panic, got %v %v", result, err)
	}

	value := 42
	result, err = protect("test", func() (*int, error) {
		return &value, nil
	})
	if err != nil || *result != 42 {
		t.Errorf("unexpected result: %v %v", result, err)
	}
}
