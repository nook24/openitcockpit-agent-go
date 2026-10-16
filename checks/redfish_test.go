package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// fakeBMC is a minimal Redfish service with session or basic authentication
type fakeBMC struct {
	mutex     sync.Mutex
	resources map[string]string
	expand    bool // supports $expand=.($levels=1)
	basicOnly bool // no session service
	failPaths map[string]int

	tokens   map[string]bool
	logins   int
	logouts  int
	requests int
}

const (
	fakeBMCUser     = "monitoring"
	fakeBMCPassword = "secret"
)

func newFakeBMC(resources map[string]string) *fakeBMC {
	return &fakeBMC{resources: resources, expand: true, tokens: map[string]bool{}, failPaths: map[string]int{}}
}

func (f *fakeBMC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.requests++

	path := r.URL.Path
	if r.Method == http.MethodPost && path == "/redfish/v1/SessionService/Sessions" {
		if f.basicOnly {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var credentials map[string]string
		_ = json.NewDecoder(r.Body).Decode(&credentials)
		if credentials["UserName"] != fakeBMCUser || credentials["Password"] != fakeBMCPassword {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": {"@Message.ExtendedInfo": [{"Message": "Invalid credentials"}]}}`))
			return
		}
		f.logins++
		token := fmt.Sprintf("token-%d", f.logins)
		f.tokens[token] = true
		w.Header().Set("X-Auth-Token", token)
		w.Header().Set("Location", fmt.Sprintf("/redfish/v1/SessionService/Sessions/%d", f.logins))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
		return
	}

	// The service root does not require authentication
	if path != "/redfish/v1" {
		user, password, basic := r.BasicAuth()
		authorized := f.tokens[r.Header.Get("X-Auth-Token")] || (basic && user == fakeBMCUser && password == fakeBMCPassword)
		if !authorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	if r.Method == http.MethodDelete && strings.HasPrefix(path, "/redfish/v1/SessionService/Sessions/") {
		f.logouts++
		delete(f.tokens, r.Header.Get("X-Auth-Token"))
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if status, ok := f.failPaths[path]; ok {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error": {"message": "fake error"}}`))
		return
	}

	key := path
	if skip := r.URL.Query().Get("$skip"); skip != "" {
		key += "?$skip=" + skip
	}
	data, ok := f.resources[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if path == "/redfish/v1" && !f.expand {
		data = strings.Replace(data, `"Levels": true`, `"Levels": false`, 1)
	}
	if f.expand && r.URL.Query().Get("$expand") != "" {
		data = f.expandMembers(data)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(data))
}

// expandMembers replaces the links of a collection by the resources
func (f *fakeBMC) expandMembers(data string) string {
	var collection map[string]interface{}
	if json.Unmarshal([]byte(data), &collection) != nil {
		return data
	}
	members, ok := collection["Members"].([]interface{})
	if !ok {
		return data
	}
	for i, member := range members {
		link, _ := member.(map[string]interface{})["@odata.id"].(string)
		if resource, ok := f.resources[link]; ok {
			var expanded interface{}
			if json.Unmarshal([]byte(resource), &expanded) == nil {
				members[i] = expanded
			}
		}
	}
	result, _ := json.Marshal(collection)
	return string(result)
}

func (f *fakeBMC) stats() (logins, logouts, requests int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.logins, f.logouts, f.requests
}

func (f *fakeBMC) expireSessions() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.tokens = map[string]bool{}
}

func redfishLink(path string) string {
	return fmt.Sprintf(`{"@odata.id": "%s"}`, path)
}

func redfishCollection(paths ...string) string {
	links := make([]string, 0, len(paths))
	for _, path := range paths {
		links = append(links, redfishLink(path))
	}
	return fmt.Sprintf(`{"Members@odata.count": %d, "Members": [%s]}`, len(paths), strings.Join(links, ","))
}

// testRedfishResources returns a server with the deprecated Thermal and Power resources
func testRedfishResources(now time.Time) map[string]string {
	recent := now.Add(-time.Hour).UTC().Format(time.RFC3339)
	newer := now.Add(-10 * time.Minute).Format("2006-01-02T15:04:05-07:00")
	old := now.Add(-48 * time.Hour).UTC().Format(time.RFC3339)

	return map[string]string{
		"/redfish/v1": `{"RedfishVersion": "1.15.0", "Vendor": "Contoso",
			"Systems": {"@odata.id": "/redfish/v1/Systems"}, "Chassis": {"@odata.id": "/redfish/v1/Chassis"},
			"Managers": {"@odata.id": "/redfish/v1/Managers"}, "SessionService": {"@odata.id": "/redfish/v1/SessionService"},
			"Links": {"Sessions": {"@odata.id": "/redfish/v1/SessionService/Sessions"}},
			"ProtocolFeaturesSupported": {"ExpandQuery": {"Levels": true, "NoLinks": true, "MaxLevels": 6}}}`,

		"/redfish/v1/Systems": redfishCollection("/redfish/v1/Systems/1"),
		"/redfish/v1/Systems/1": `{"@odata.id": "/redfish/v1/Systems/1", "Id": "1", "Name": "System", "Manufacturer": "Contoso", "Model": "3500",
			"SerialNumber": "437XR1138R2", "BiosVersion": "P79 v1.45", "PowerState": "On",
			"Status": {"State": "Enabled", "Health": "OK", "HealthRollup": "Warning", "Conditions": [{"Message": "Power supply 'PSU 2' failed.", "Severity": "Critical"}]},
			"ProcessorSummary": {"Count": 2, "Status": {"State": "Enabled", "Health": "OK", "HealthRollup": "OK"}},
			"MemorySummary": {"TotalSystemMemoryGiB": 96, "Status": {"State": "Enabled", "Health": "OK", "HealthRollup": "OK"}},
			"Storage": {"@odata.id": "/redfish/v1/Systems/1/Storage"}, "LogServices": {"@odata.id": "/redfish/v1/Systems/1/LogServices"}}`,
		"/redfish/v1/Systems/1/Storage": redfishCollection("/redfish/v1/Systems/1/Storage/RAID"),
		"/redfish/v1/Systems/1/Storage/RAID": `{"@odata.id": "/redfish/v1/Systems/1/Storage/RAID", "Id": "RAID", "Name": "RAID Controller",
			"Status": {"State": "Enabled", "Health": "Warning", "HealthRollup": "Warning"},
			"StorageControllers": [{"Name": "Contoso HW RAID", "Model": "RAID 16", "FirmwareVersion": "23.13", "Status": {"State": "Enabled", "Health": "OK"}}],
			"Drives": [{"@odata.id": "/redfish/v1/Chassis/1/Drives/0"}, {"@odata.id": "/redfish/v1/Chassis/1/Drives/1"}, {"@odata.id": "/redfish/v1/Chassis/1/Drives/2"}],
			"Volumes": {"@odata.id": "/redfish/v1/Systems/1/Storage/RAID/Volumes"}}`,
		"/redfish/v1/Chassis/1/Drives/0": `{"Id": "0", "Name": "Disk 0", "Model": "SAS 18000 ", "SerialNumber": "S0", "MediaType": "HDD", "Protocol": "SAS",
			"CapacityBytes": 18000000000000, "FailurePredicted": false, "Status": {"State": "Enabled", "Health": "OK"}}`,
		"/redfish/v1/Chassis/1/Drives/1": `{"Id": "1", "Name": "Disk 1", "Model": "SSD 960", "SerialNumber": "S1", "MediaType": "SSD", "Protocol": "SATA",
			"CapacityBytes": 960000000000, "FailurePredicted": true, "PredictedMediaLifeLeftPercent": 3, "Status": {"State": "Enabled", "Health": "Warning"}}`,
		"/redfish/v1/Chassis/1/Drives/2":             `{"Id": "2", "Name": "Empty bay", "Status": {"State": "Absent"}}`,
		"/redfish/v1/Systems/1/Storage/RAID/Volumes": redfishCollection("/redfish/v1/Systems/1/Storage/RAID/Volumes/1"),
		"/redfish/v1/Systems/1/Storage/RAID/Volumes/1": `{"Id": "1", "Name": "Boot", "RAIDType": "RAID1", "CapacityBytes": 960000000000,
			"Status": {"State": "Enabled", "Health": "Warning"}}`,
		// Uses @odata.nextLink and ignores the $skip parameter, like the DMTF mockup server
		"/redfish/v1/Systems/1/LogServices": redfishCollection("/redfish/v1/Systems/1/LogServices/Log1"),
		"/redfish/v1/Systems/1/LogServices/Log1": `{"@odata.id": "/redfish/v1/Systems/1/LogServices/Log1", "Id": "Log1",
			"Entries": {"@odata.id": "/redfish/v1/Systems/1/LogServices/Log1/Entries"}}`,
		"/redfish/v1/Systems/1/LogServices/Log1/Entries": `{"Members": [
				{"@odata.id": "/redfish/v1/Systems/1/LogServices/Log1/Entries/1", "Severity": "Critical", "Created": "` + recent + `", "Message": "Temperature threshold exceeded"}],
			"@odata.nextLink": "/redfish/v1/Systems/1/LogServices/Log1/Entries?$skip=1"}`,
		"/redfish/v1/Systems/1/LogServices/Log1/Entries?$skip=1": `{"Members": [
				{"@odata.id": "/redfish/v1/Systems/1/LogServices/Log1/Entries/1", "Severity": "Critical", "Created": "` + recent + `", "Message": "Temperature threshold exceeded"}],
			"@odata.nextLink": "/redfish/v1/Systems/1/LogServices/Log1/Entries?$skip=1"}`,

		"/redfish/v1/Chassis": redfishCollection("/redfish/v1/Chassis/1"),
		"/redfish/v1/Chassis/1": `{"@odata.id": "/redfish/v1/Chassis/1", "Id": "1", "Name": "1U", "ChassisType": "RackMount", "Manufacturer": "Contoso",
			"Status": {"State": "Enabled", "Health": "Critical"},
			"Thermal": {"@odata.id": "/redfish/v1/Chassis/1/Thermal"}, "Power": {"@odata.id": "/redfish/v1/Chassis/1/Power"},
			"ThermalSubsystem": {"@odata.id": "/redfish/v1/Chassis/1/ThermalSubsystem"}}`,
		"/redfish/v1/Chassis/1/Thermal": `{"Temperatures": [
				{"Name": "CPU1 Temp", "ReadingCelsius": 41, "UpperThresholdNonCritical": 42, "UpperThresholdCritical": 45, "PhysicalContext": "CPU", "Status": {"State": "Enabled", "Health": "OK"}},
				{"Name": "CPU2 Temp", "Status": {"State": "Absent"}},
				{"Name": "Intake Temp", "ReadingCelsius": null, "Status": {"State": "Enabled"}}],
			"Fans": [{"FanName": "Fan 1", "Reading": 2100, "ReadingUnits": "RPM", "LowerThresholdNonCritical": 500, "LowerThresholdCritical": 300, "Status": {"State": "Enabled", "Health": "OK"}}],
			"Redundancy": [{"Name": "Fan Redundancy", "Mode": "N+m", "Status": {"State": "Enabled", "Health": "OK"}}]}`,
		"/redfish/v1/Chassis/1/Power": `{"PowerControl": [{"PowerConsumedWatts": 344, "PowerCapacityWatts": 800}],
			"PowerSupplies": [
				{"Name": "PSU 1", "Model": "RKS-440", "PowerCapacityWatts": 400, "LastPowerOutputWatts": 172, "Status": {"State": "Enabled", "Health": "OK"}},
				{"Name": "PSU 2", "Model": "RKS-440", "PowerCapacityWatts": 400, "Status": {"State": "Enabled", "Health": "Critical"}}],
			"Redundancy": [{"Name": "PSU Redundancy", "Mode": "Failover", "Status": {"State": "Enabled", "Health": "Critical"}}]}`,

		"/redfish/v1/Managers": redfishCollection("/redfish/v1/Managers/BMC"),
		"/redfish/v1/Managers/BMC": `{"@odata.id": "/redfish/v1/Managers/BMC", "Id": "BMC", "Name": "Manager", "Model": "Joo Janta 200", "FirmwareVersion": "1.45",
			"Status": {"State": "Enabled", "Health": "OK"}, "LogServices": {"@odata.id": "/redfish/v1/Managers/BMC/LogServices"}}`,
		"/redfish/v1/Managers/BMC/LogServices": redfishCollection("/redfish/v1/Managers/BMC/LogServices/Sel", "/redfish/v1/Managers/BMC/LogServices/Lclog"),
		"/redfish/v1/Managers/BMC/LogServices/Sel": `{"@odata.id": "/redfish/v1/Managers/BMC/LogServices/Sel", "Id": "Sel", "ServiceEnabled": true,
			"Entries": {"@odata.id": "/redfish/v1/Managers/BMC/LogServices/Sel/Entries"}}`,
		"/redfish/v1/Managers/BMC/LogServices/Lclog": `{"@odata.id": "/redfish/v1/Managers/BMC/LogServices/Lclog", "Id": "Lclog",
			"Entries": {"@odata.id": "/redfish/v1/Managers/BMC/LogServices/Lclog/Entries"}}`,
		"/redfish/v1/Managers/BMC/LogServices/Sel/Entries": `{"Members": [
				{"Id": "1", "Severity": "Critical", "Created": "` + recent + `", "Message": "PSU 2 failed", "MessageId": "PSU0001"},
				{"Id": "2", "Severity": "Warning", "Created": "` + old + `", "Message": "Old warning", "MessageId": "TMP0001"},
				{"Id": "3", "Severity": "OK", "Created": "` + recent + `", "Message": "System booted", "MessageId": "SYS0001"}],
			"Members@odata.nextLink": "/redfish/v1/Managers/BMC/LogServices/Sel/Entries?$skip=3"}`,
		"/redfish/v1/Managers/BMC/LogServices/Sel/Entries?$skip=3": `{"Members": [
				{"Id": "4", "Severity": "Warning", "Created": "` + newer + `", "Message": "Fan 1 speed low", "MessageId": "FAN0001"}]}`,
	}
}

// testRedfishNewModelResources returns a chassis with ThermalSubsystem, PowerSubsystem and sensors only
func testRedfishNewModelResources(now time.Time) map[string]string {
	resources := testRedfishResources(now)
	resources["/redfish/v1/Chassis/1"] = `{"Id": "1", "Name": "Liquid cooled", "Status": {"State": "Enabled", "Health": "OK"},
		"ThermalSubsystem": {"@odata.id": "/redfish/v1/Chassis/1/ThermalSubsystem"}, "PowerSubsystem": {"@odata.id": "/redfish/v1/Chassis/1/PowerSubsystem"},
		"Sensors": {"@odata.id": "/redfish/v1/Chassis/1/Sensors"}, "EnvironmentMetrics": {"@odata.id": "/redfish/v1/Chassis/1/EnvironmentMetrics"}}`
	resources["/redfish/v1/Chassis/1/ThermalSubsystem"] = `{"Fans": {"@odata.id": "/redfish/v1/Chassis/1/ThermalSubsystem/Fans"},
		"FanRedundancy": [{"RedundancyType": "NPlusM", "Status": {"State": "Enabled", "Health": "OK"}}]}`
	resources["/redfish/v1/Chassis/1/ThermalSubsystem/Fans"] = redfishCollection("/redfish/v1/Chassis/1/ThermalSubsystem/Fans/Bay1")
	resources["/redfish/v1/Chassis/1/ThermalSubsystem/Fans/Bay1"] = `{"Name": "Fan Bay 1", "Status": {"State": "Enabled", "Health": "Warning"}, "SpeedPercent": {"Reading": 45, "SpeedRPM": 2200}}`
	resources["/redfish/v1/Chassis/1/Sensors"] = redfishCollection("/redfish/v1/Chassis/1/Sensors/CPU1Temp", "/redfish/v1/Chassis/1/Sensors/FanBay1")
	resources["/redfish/v1/Chassis/1/Sensors/CPU1Temp"] = `{"Name": "CPU #1 Temperature", "Reading": 44, "ReadingType": "Temperature", "ReadingUnits": "Cel",
		"Status": {"State": "Enabled", "Health": "Warning", "Conditions": [{"Message": "Sensor 'CPU1 Temp' reading of 44 (Cel) is above the 42 upper caution threshold."}]},
		"Thresholds": {"UpperCaution": {"Reading": 42}, "UpperCritical": {"Reading": 45}}}`
	resources["/redfish/v1/Chassis/1/Sensors/FanBay1"] = `{"Name": "Chassis Fan #1", "Reading": 45, "ReadingType": "Percent", "ReadingUnits": "%", "Status": {"State": "Enabled", "Health": "OK"}}`
	resources["/redfish/v1/Chassis/1/PowerSubsystem"] = `{"CapacityWatts": 2000, "PowerSupplies": {"@odata.id": "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies"},
		"PowerSupplyRedundancy": [{"RedundancyType": "Failover", "Status": {"State": "Enabled", "Health": "OK"}}]}`
	resources["/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies"] = redfishCollection("/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/Bay1")
	resources["/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/Bay1"] = `{"Name": "Power Supply Bay 1", "PowerCapacityWatts": 400,
		"Status": {"State": "Enabled", "Health": "Warning", "Conditions": [{"Message": "Power supply 'PSU 1' has a predicted failure condition."}]}}`
	resources["/redfish/v1/Chassis/1/EnvironmentMetrics"] = `{"PowerWatts": {"Reading": 374}}`
	return resources
}

func testRedfishDefinition(url string) *config.RedfishDefinition {
	eventlog := true
	return &config.RedfishDefinition{
		Name:                   "server01",
		Enabled:                true,
		URL:                    url,
		Username:               fakeBMCUser,
		Password:               fakeBMCPassword,
		Interval:               60,
		Timeout:                5,
		Eventlog:               &eventlog,
		EventlogWindow:         86400,
		EventlogServices:       config.RedfishDefaultEventlogServices,
		EventlogServicesRegexp: regexp.MustCompile(config.RedfishDefaultEventlogServices),
	}
}

func TestRedfishCollectDeprecatedThermalAndPower(t *testing.T) {
	now := time.Now()
	bmc := newFakeBMC(testRedfishResources(now))
	server := httptest.NewServer(bmc)
	defer server.Close()

	def := testRedfishDefinition(server.URL)
	client := newRedfishClient(def)
	result, err := collectRedfish(context.Background(), client, def, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", result.Warnings)
	}
	if result.Vendor != "Contoso" || result.RedfishVersion != "1.15.0" || result.Requests == 0 || result.CollectedAt != now.Unix() {
		t.Errorf("unexpected result: %+v", result)
	}

	systems := result.Systems.([]*resultRedfishSystem)
	if len(systems) != 1 {
		t.Fatalf("unexpected systems: %+v", systems)
	}
	if s := systems[0]; s.PowerState != "On" || s.Status.HealthRollup != "Warning" || len(s.Status.Conditions) != 1 || s.ProcessorCount != 2 || s.Memory.Health != "OK" || s.MemoryGiB != 96 {
		t.Errorf("unexpected system: %+v", s)
	}

	chassis := result.Chassis.([]*resultRedfishChassis)
	if len(chassis) != 1 {
		t.Fatalf("unexpected chassis: %+v", chassis)
	}
	c := chassis[0]
	// The deprecated Thermal resource is preferred, so the ThermalSubsystem (not part of the fake BMC) is not requested
	if len(c.Temperatures) != 2 || *c.Temperatures[0].Reading != 41 || *c.Temperatures[0].UpperWarning != 42 || *c.Temperatures[0].UpperCritical != 45 || c.Temperatures[1].Reading != nil {
		t.Errorf("unexpected temperatures: %+v", c.Temperatures)
	}
	if len(c.Fans) != 1 || c.Fans[0].Name != "Fan 1" || c.Fans[0].Units != "RPM" || *c.Fans[0].LowerCritical != 300 {
		t.Errorf("unexpected fans: %+v", c.Fans)
	}
	if len(c.PowerSupplies) != 2 || c.PowerSupplies[1].Status.Health != "Critical" || *c.PowerSupplies[0].OutputWatts != 172 {
		t.Errorf("unexpected power supplies: %+v", c.PowerSupplies)
	}
	if *c.PowerConsumedWatts != 344 || *c.PowerCapacityWatts != 800 {
		t.Errorf("unexpected power consumption: %v %v", *c.PowerConsumedWatts, *c.PowerCapacityWatts)
	}
	if len(c.Redundancy) != 2 || c.Redundancy[0].Group != "fans" || c.Redundancy[1].Group != "power_supplies" || c.Redundancy[1].Status.Health != "Critical" {
		t.Errorf("unexpected redundancy: %+v", c.Redundancy)
	}

	storage := result.Storage.([]*resultRedfishStorage)
	if len(storage) != 1 || storage[0].System != "1" || len(storage[0].Controllers) != 1 {
		t.Fatalf("unexpected storage: %+v", storage)
	}
	if d := storage[0].Drives; len(d) != 2 || d[0].Model != "SAS 18000" || !d[1].FailurePredicted || *d[1].LifeLeftPercent != 3 {
		t.Errorf("unexpected drives (the absent bay is expected to be skipped): %+v", d)
	}
	if v := storage[0].Volumes; len(v) != 1 || v[0].RAIDType != "RAID1" || v[0].Status.Health != "Warning" {
		t.Errorf("unexpected volumes: %+v", v)
	}

	if m := result.Managers.([]*resultRedfishManager); len(m) != 1 || m[0].FirmwareVersion != "1.45" {
		t.Errorf("unexpected managers: %+v", m)
	}

	eventlog := result.Eventlog.(*resultRedfishEventlog)
	// Lclog does not match the default regular expression, the old and the OK entry are skipped, the second page is read.
	// The duplicate entry of the system log (the page ignores $skip) is removed
	if len(eventlog.Services) != 2 || len(eventlog.Entries) != 3 {
		t.Fatalf("unexpected eventlog: %+v", eventlog)
	}
	if eventlog.Entries[0].Message != "Fan 1 speed low" || eventlog.Entries[1].Severity != "Critical" || eventlog.Entries[2].Severity != "Critical" {
		t.Errorf("expected the newest entry first: %+v %+v", eventlog.Entries[0], eventlog.Entries[1])
	}

	// The session is reused by the next collection
	if _, err := collectRedfish(context.Background(), client, def, now); err != nil {
		t.Fatal(err)
	}
	if logins, _, _ := bmc.stats(); logins != 1 {
		t.Errorf("expected a single login, got %d", logins)
	}

	// An expired session leads to a new login
	bmc.expireSessions()
	if _, err := collectRedfish(context.Background(), client, def, now); err != nil {
		t.Fatal(err)
	}
	if logins, _, _ := bmc.stats(); logins != 2 {
		t.Errorf("expected a new login after the session expired, got %d logins", logins)
	}

	client.logout()
	if _, logouts, _ := bmc.stats(); logouts != 1 {
		t.Errorf("expected the session to be deleted, got %d logouts", logouts)
	}
}

func TestRedfishCollectWithoutExpand(t *testing.T) {
	now := time.Now()
	bmcExpand := newFakeBMC(testRedfishResources(now))
	serverExpand := httptest.NewServer(bmcExpand)
	defer serverExpand.Close()
	bmc := newFakeBMC(testRedfishResources(now))
	bmc.expand = false
	server := httptest.NewServer(bmc)
	defer server.Close()

	withExpand, err := collectRedfish(context.Background(), newRedfishClient(testRedfishDefinition(serverExpand.URL)), testRedfishDefinition(serverExpand.URL), now)
	if err != nil {
		t.Fatal(err)
	}
	without, err := collectRedfish(context.Background(), newRedfishClient(testRedfishDefinition(server.URL)), testRedfishDefinition(server.URL), now)
	if err != nil {
		t.Fatal(err)
	}
	if without.Requests <= withExpand.Requests {
		t.Errorf("expected more requests without $expand: %d <= %d", without.Requests, withExpand.Requests)
	}
	if len(without.Chassis.([]*resultRedfishChassis)[0].PowerSupplies) != 2 || len(without.Storage.([]*resultRedfishStorage)[0].Drives) != 2 {
		t.Errorf("unexpected result without $expand: %+v", without)
	}
}

func TestRedfishCollectNewModel(t *testing.T) {
	now := time.Now()
	server := httptest.NewServer(newFakeBMC(testRedfishNewModelResources(now)))
	defer server.Close()

	def := testRedfishDefinition(server.URL)
	result, err := collectRedfish(context.Background(), newRedfishClient(def), def, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", result.Warnings)
	}
	c := result.Chassis.([]*resultRedfishChassis)[0]
	// Only the temperature sensor is a temperature, the fan sensor is ignored
	if len(c.Temperatures) != 1 || *c.Temperatures[0].Reading != 44 || *c.Temperatures[0].UpperWarning != 42 || *c.Temperatures[0].UpperCritical != 45 || len(c.Temperatures[0].Status.Conditions) != 1 {
		t.Errorf("unexpected temperatures: %+v", c.Temperatures)
	}
	if len(c.Fans) != 1 || *c.Fans[0].Reading != 45 || c.Fans[0].Units != "%" || c.Fans[0].Status.Health != "Warning" {
		t.Errorf("unexpected fans: %+v", c.Fans)
	}
	if len(c.PowerSupplies) != 1 || c.PowerSupplies[0].Status.Health != "Warning" || *c.PowerConsumedWatts != 374 || *c.PowerCapacityWatts != 2000 {
		t.Errorf("unexpected power: %+v %v", c.PowerSupplies, c.PowerConsumedWatts)
	}
	if len(c.Redundancy) != 2 || c.Redundancy[0].Mode != "NPlusM" || c.Redundancy[1].Mode != "Failover" {
		t.Errorf("unexpected redundancy: %+v", c.Redundancy)
	}
}

func TestRedfishBasicAuthAndLoginErrors(t *testing.T) {
	now := time.Now()
	bmc := newFakeBMC(testRedfishResources(now))
	bmc.basicOnly = true
	server := httptest.NewServer(bmc)
	defer server.Close()

	def := testRedfishDefinition(server.URL)
	if _, err := collectRedfish(context.Background(), newRedfishClient(def), def, now); err != nil {
		t.Fatalf("expected basic authentication without session service: %s", err)
	}

	def.Password = "wrong"
	if _, err := collectRedfish(context.Background(), newRedfishClient(def), def, now); err == nil || !strings.Contains(err.Error(), "check username and password") {
		t.Errorf("expected an authentication error with basic authentication, got: %v", err)
	}

	bmc.basicOnly = false
	_, err := collectRedfish(context.Background(), newRedfishClient(def), def, now)
	if err == nil || !strings.Contains(err.Error(), "login failed") || !strings.Contains(err.Error(), "Invalid credentials") {
		t.Errorf("expected a login error, got: %v", err)
	}
}

func TestRedfishPartialErrors(t *testing.T) {
	now := time.Now()
	bmc := newFakeBMC(testRedfishResources(now))
	bmc.failPaths["/redfish/v1/Chassis/1/Power"] = http.StatusInternalServerError
	bmc.failPaths["/redfish/v1/Managers/BMC/LogServices"] = http.StatusForbidden
	bmc.failPaths["/redfish/v1/Systems/1/LogServices"] = http.StatusForbidden
	server := httptest.NewServer(bmc)
	defer server.Close()

	def := testRedfishDefinition(server.URL)
	result, err := collectRedfish(context.Background(), newRedfishClient(def), def, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "power of chassis 1") || !strings.Contains(result.Warnings[0], "500") {
		t.Errorf("expected a warning for the power resource: %v", result.Warnings)
	}
	if c := result.Chassis.([]*resultRedfishChassis)[0]; len(c.Temperatures) != 2 || len(c.PowerSupplies) != 0 {
		t.Errorf("expected the thermal data without power data: %+v", c)
	}
	if e, ok := result.Eventlog.(map[string]string); !ok || !strings.Contains(e["error"], "403") {
		t.Errorf("expected an error for the eventlog: %+v", result.Eventlog)
	}

	// The BMC is not reachable
	server.Close()
	if _, err := collectRedfish(context.Background(), newRedfishClient(def), def, now); err == nil {
		t.Error("expected an error for an unreachable BMC")
	}
}

func TestRedfishFingerprint(t *testing.T) {
	now := time.Now()
	server := httptest.NewTLSServer(newFakeBMC(testRedfishResources(now)))
	defer server.Close()
	fingerprint := sha256.Sum256(server.Certificate().Raw)

	def := testRedfishDefinition(server.URL)
	if _, err := collectRedfish(context.Background(), newRedfishClient(def), def, now); err == nil {
		t.Error("expected an error for the self signed certificate")
	}

	def.FingerprintBytes = fingerprint[:]
	if _, err := collectRedfish(context.Background(), newRedfishClient(def), def, now); err != nil {
		t.Errorf("expected the certificate to be accepted with the fingerprint: %s", err)
	}

	wrong, _ := hex.DecodeString(strings.Repeat("ab", 32))
	def.FingerprintBytes = wrong
	if _, err := collectRedfish(context.Background(), newRedfishClient(def), def, now); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("expected a fingerprint error, got: %v", err)
	}

	def.FingerprintBytes = nil
	def.SkipVerify = true
	if _, err := collectRedfish(context.Background(), newRedfishClient(def), def, now); err != nil {
		t.Errorf("expected the certificate to be accepted with skip_verify: %s", err)
	}
}

func TestCheckRedfishCollectors(t *testing.T) {
	bmc := newFakeBMC(testRedfishResources(time.Now()))
	server := httptest.NewServer(bmc)
	defer server.Close()

	def := testRedfishDefinition(server.URL)
	invalid := testRedfishDefinition(server.URL)
	invalid.Name = "invalid"
	invalid.ConfigError = "invalid url"
	check := &CheckRedfish{definitions: []*config.RedfishDefinition{def, invalid}}

	r, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e := r.(map[string]interface{})["invalid"].(map[string]string); e["error"] != "invalid url" {
		t.Errorf("expected the configuration error: %+v", e)
	}

	// The first collection runs in the background
	var result *resultRedfish
	deadline := time.Now().Add(5 * time.Second)
	for result == nil && time.Now().Before(deadline) {
		r, _ = check.Run(context.Background())
		switch value := r.(map[string]interface{})["server01"].(type) {
		case *resultRedfish:
			result = value
		case map[string]interface{}:
			if value["pending"] != true {
				t.Fatalf("unexpected result: %+v", value)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if result == nil || len(result.Systems.([]*resultRedfishSystem)) != 1 {
		t.Fatalf("no result of the background collector: %+v", r)
	}

	// A changed definition replaces the collector, the old one deletes its session
	changed := testRedfishDefinition(server.URL)
	changed.Timeout = 6
	check.definitions = []*config.RedfishDefinition{changed}
	if _, err := check.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, logouts, _ := bmc.stats(); logouts >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, logouts, _ := bmc.stats(); logouts < 1 {
		t.Error("expected the old collector to delete its session")
	}

	redfishCollectors.Lock()
	count := len(redfishCollectors.collectors)
	for key, collector := range redfishCollectors.collectors {
		collector.close()
		delete(redfishCollectors.collectors, key)
	}
	redfishCollectors.Unlock()
	if count != 1 {
		t.Errorf("expected a single collector, got %d", count)
	}
}

func TestRedfishMembersLimit(t *testing.T) {
	// A log service with 300 expanded entries and a collection with 300 links
	var requests atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/expanded", func(w http.ResponseWriter, r *http.Request) {
		members := make([]map[string]interface{}, 300)
		for i := range members {
			members[i] = map[string]interface{}{"@odata.id": fmt.Sprintf("/redfish/v1/expanded/%d", i), "Id": strconv.Itoa(i), "Severity": "OK"}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Members": members})
	})
	mux.HandleFunc("/redfish/v1/links", func(w http.ResponseWriter, r *http.Request) {
		members := make([]map[string]string, 300)
		for i := range members {
			members[i] = map[string]string{"@odata.id": fmt.Sprintf("/redfish/v1/links/%d", i)}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Members": members})
	})
	mux.HandleFunc("/redfish/v1/links/", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"@odata.id": r.URL.Path, "Id": path.Base(r.URL.Path)})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	def := testRedfishDefinition(server.URL)
	def.Username = ""
	client := newRedfishClient(def)

	// Expanded members do not count against the limit of the requests
	members, err := client.members(context.Background(), "/redfish/v1/expanded")
	if err != nil || len(members) != 300 {
		t.Fatalf("expected 300 expanded members, got %d (%v)", len(members), err)
	}
	// Links are requested one by one up to the limit
	members, err = client.members(context.Background(), "/redfish/v1/links")
	if err != nil || len(members) != redfishMaxResolve || requests.Load() != redfishMaxResolve {
		t.Fatalf("expected %d resolved members and requests, got %d and %d (%v)", redfishMaxResolve, len(members), requests.Load(), err)
	}
	if len(client.warnings) != 1 || !strings.Contains(client.warnings[0], "only the first 200 of 300 members") {
		t.Errorf("expected a warning, got %v", client.warnings)
	}
}
