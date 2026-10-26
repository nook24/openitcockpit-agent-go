package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestChecksCheckLaunchdServices(t *testing.T) {
	checks := []Check{
		&CheckLaunchd{},
	}

	for _, c := range checks {
		if c.Name() == "" {
			t.Error("Invalid name")
		}
		r, err := c.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if r == nil {
			t.Fatal("invalid result")
		}
		js, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(js))
	}
}

func TestGetServiceListFromLaunchctl(t *testing.T) {

	check := &CheckLaunchd{}
	results, err := check.getServiceListViaLaunchctl(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(results) == 0 {
		t.Fatal("Empty result from launchctl list")
	}

	// The Finder only runs in a GUI session, which does not exist on build servers or via SSH.
	// Services of Apple exist in every launchd domain.
	foundApple := false
	for _, result := range results {
		if strings.HasPrefix(result.Label, "com.apple.") {
			foundApple = true
			break
		}
	}
	if !foundApple {
		t.Fatal("no service of Apple (com.apple.*) found")
	}
}
