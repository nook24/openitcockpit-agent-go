package checks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
	"github.com/yusufpapurcu/wmi"
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

func TestIsWMINotFound(t *testing.T) {
	// The error messages are localized, e.g. "Ungültiger Namespace" on German systems
	var dst []antiVirusProduct
	err := wmi.QueryNamespace("SELECT displayName FROM AntiVirusProduct", &dst, `root\OitcDoesNotExist`)
	if err == nil || !isWMINotFound(err) {
		t.Errorf("missing namespace not detected: %v", err)
	}
	err = wmi.Query("SELECT DisplayName FROM Oitc_DoesNotExist", &dst)
	if err == nil || !isWMINotFound(err) {
		t.Errorf("missing class not detected: %v", err)
	}
	if isWMINotFound(errors.New("access denied")) {
		t.Error("other errors must not be detected as missing namespace or class")
	}
}
