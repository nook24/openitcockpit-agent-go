package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	systemdutil "github.com/coreos/go-systemd/v22/util"
)

func TestChecksCheckSystemdServices(t *testing.T) {
	if !systemdutil.IsRunningSystemd() {
		t.Skip("systemd is not running (e.g. a container)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	c := &CheckSystemd{}
	if c.Name() == "" {
		t.Error("Invalid name")
	}
	r, err := c.Run(ctx)
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

func TestGetServiceListFromDbus(t *testing.T) {
	if !systemdutil.IsRunningSystemd() {
		t.SkipNow()
	}

	c := &CheckSystemd{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	r, err := c.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	results := r.([]*resultSystemdServices)

	if len(results) == 0 {
		t.Fatal("Empty result from systemd / dbus")
	}

	// The dbus service is available and running - because we ask dbus
	// systemd-journald is part of every system running systemd. dbus is not a good needle,
	// as Fedora and Arch Linux use dbus-broker.service
	needle := "systemd-journald.service"
	foundNeedle := false
	for _, result := range results {
		if result.Name == needle {
			foundNeedle = true
			if result.ActiveState != "active" {
				t.Errorf("%s is not active: %s/%s", needle, result.ActiveState, result.SubState)
			}
		}
	}

	if !foundNeedle {
		t.Fatal("Needle not found: " + needle)
	}
}
