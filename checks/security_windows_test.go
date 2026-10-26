package checks

import (
	"context"
	"encoding/json"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

func TestCheckSecurityWindows(t *testing.T) {
	r, err := (&CheckSecurity{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(js))

	result := r.(map[string]interface{})
	firewall, ok := result["firewall"].(*resultWindowsFirewall)
	if !ok {
		t.Fatalf("unexpected firewall result: %+v", result["firewall"])
	}
	for _, profile := range []string{"domain", "private", "public"} {
		if _, ok := firewall.Profiles[profile]; !ok {
			t.Errorf("missing firewall profile %s", profile)
		}
	}
	if _, ok := result["defender"].(*resultWindowsDefender); !ok {
		t.Errorf("unexpected defender result: %+v", result["defender"])
	}
	if _, ok := result["antivirus"].([]*resultAntivirusProduct); !ok {
		t.Errorf("unexpected antivirus result: %+v", result["antivirus"])
	}
}

func TestCheckWindowsScheduledTasks(t *testing.T) {
	for _, includeMicrosoft := range []bool{false, true} {
		c := &CheckWindowsScheduledTasks{includeMicrosoft: includeMicrosoft}
		r, err := c.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		tasks := r.([]*resultWindowsScheduledTask)
		microsoftTasks := 0
		for _, task := range tasks {
			if strings.HasPrefix(strings.ToLower(task.Path), `\microsoft\`) {
				microsoftTasks++
			}
		}
		if includeMicrosoft && microsoftTasks == 0 {
			t.Error("expected tasks of the \\Microsoft\\ folder")
		}
		if !includeMicrosoft && microsoftTasks > 0 {
			t.Errorf("tasks of the \\Microsoft\\ folder must be excluded: %d", microsoftTasks)
		}
		js, _ := json.Marshal(tasks[:min(len(tasks), 3)])
		t.Logf("include microsoft=%v: %d tasks, e.g. %s", includeMicrosoft, len(tasks), js)
	}
}

func TestCheckWindowsPerfCounter(t *testing.T) {
	c := &CheckWindowsPerfCounter{}
	definitions := []*config.PerfCounterDefinition{
		{Name: "cpu_total", Counter: `\Processor(_Total)\% Processor Time`},
		{Name: "cpu_cores", Counter: `\Processor(*)\% Processor Time`},
		{Name: "memory", Counter: `\Memory\Available MBytes`},
		{Name: "unknown_object", Counter: `\Does Not Exist\Foo`},
		{Name: "invalid", ConfigError: "invalid counter"},
	}
	if enabled, _ := c.Configure(&config.Configuration{PerfCounterConfiguration: definitions}); !enabled {
		t.Fatal("check should be enabled")
	}
	defer c.Configure(&config.Configuration{})

	for run := 1; run <= 2; run++ {
		r, err := c.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		results := r.(map[string]interface{})
		js, _ := json.Marshal(results)
		t.Logf("run %d: %s", run, js)

		total, ok := results["cpu_total"].(*resultPerfCounter)
		if !ok || len(total.Values) != 1 || total.Values[0].Instance != "_Total" || total.Values[0].Value < 0 || total.Values[0].Value > 100 {
			t.Errorf("unexpected cpu_total: %s", js)
		}
		if cores, ok := results["cpu_cores"].(*resultPerfCounter); !ok || len(cores.Values) < 2 {
			t.Errorf("expected values for all cores and _Total: %s", js)
		}
		// Counters without instances have an empty instance name
		if memory, ok := results["memory"].(*resultPerfCounter); !ok || len(memory.Values) != 1 || memory.Values[0].Instance != "" || memory.Values[0].Value <= 0 {
			t.Errorf("unexpected memory: %s", js)
		}
		for _, name := range []string{"unknown_object", "invalid"} {
			if res, ok := results[name].(map[string]string); !ok || res["error"] == "" {
				t.Errorf("expected error for %s: %s", name, js)
			}
		}
	}
}

// variantDateToTime must return the same time as VariantTimeToSystemTime of Windows (only usable on amd64, it crashes
// the agent on ARM64)
func TestVariantDateToTime(t *testing.T) {
	values := []float64{0, 1, 2.5, 36526, 45000.5, 45000.999994, 46325.6789, 46325.000006, 73050.25, -1.25, -0.5}
	for _, value := range values {
		got := variantDateToTime(value, time.UTC)
		if runtime.GOARCH != "amd64" {
			continue
		}
		want, err := ole.GetVariantDate(math.Float64bits(value))
		if err != nil {
			t.Fatalf("%v: %s", value, err)
		}
		if !got.Equal(want) {
			t.Errorf("%v: got %s, want %s", value, got, want)
		}
	}
	if got := variantDateToTime(45000.5, time.UTC); !got.Equal(time.Date(2023, 3, 15, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("unexpected time: %s", got)
	}
	if got := variantDateToTime(-1.25, time.UTC); !got.Equal(time.Date(1899, 12, 29, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("unexpected time of a negative date: %s", got)
	}
}
