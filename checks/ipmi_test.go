package checks

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bougou/go-ipmi/pkg/types"
)

func collectIpmiReplay(t *testing.T, reader *ipmiReader, name string) *resultIpmi {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := newIpmiReplayClient(t, name)
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	result, err := reader.collect(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func ipmiSensorByName(t *testing.T, result *resultIpmi, name string) *resultIpmiSensor {
	t.Helper()
	for _, sensor := range result.Sensors {
		if sensor.Name == name {
			return sensor
		}
	}
	t.Fatalf("sensor %s not found", name)
	return nil
}

func TestIpmiReplayHealthy(t *testing.T) {
	reader := newIpmiReader(24 * time.Hour)
	result := collectIpmiReplay(t, reader, "healthy.json")

	if result.Device == nil || result.Device.IPMIVersion != "2.0" || result.Device.FirmwareRevision != "9.08" {
		t.Errorf("unexpected device: %+v", result.Device)
	}
	if result.Chassis == nil || result.Chassis.Intrusion || result.Chassis.CoolingFault {
		t.Errorf("unexpected chassis: %+v", result.Chassis)
	}
	if len(result.Sensors) != 12 || len(result.Errors) != 0 {
		t.Fatalf("expected 12 sensors without errors, got %d sensors, errors %v", len(result.Sensors), result.Errors)
	}
	for _, sensor := range result.Sensors {
		if sensor.State != "ok" {
			t.Errorf("sensor %s: expected ok, got %s (%v %s)", sensor.Name, sensor.State, sensor.States, sensor.Error)
		}
	}

	inlet := ipmiSensorByName(t, result, "Inlet Temp")
	if inlet.Reading == nil || *inlet.Reading != 24 || inlet.Unit != "degrees C" || inlet.Status != "ok" || inlet.Type != "Temperature" {
		t.Errorf("unexpected inlet temperature: %+v", inlet)
	}
	if inlet.Thresholds == nil || inlet.Thresholds.UpperNonCritical == nil || *inlet.Thresholds.UpperNonCritical != 40 ||
		*inlet.Thresholds.UpperCritical != 45 || inlet.Thresholds.LowerCritical != nil {
		t.Errorf("unexpected thresholds: %+v", inlet.Thresholds)
	}
	fan := ipmiSensorByName(t, result, "Fan1")
	if fan.Reading == nil || *fan.Reading != 4800 || fan.Unit != "RPM" || *fan.Thresholds.LowerCritical != 600 {
		t.Errorf("unexpected fan: %v %s %v", *fan.Reading, fan.Unit, *fan.Thresholds.LowerCritical)
	}
	volt := ipmiSensorByName(t, result, "Voltage 12V")
	if volt.Reading == nil || *volt.Reading < 12.05 || *volt.Reading > 12.07 {
		t.Errorf("unexpected voltage: %v", *volt.Reading)
	}
	psu := ipmiSensorByName(t, result, "PS1 Status")
	if psu.Reading != nil || len(psu.States) != 1 || psu.States[0] != "Presence detected" {
		t.Errorf("unexpected power supply: %+v", psu)
	}

	if result.Sel == nil || result.Sel.Entries != 0 || len(result.Sel.Events) != 0 {
		t.Errorf("unexpected sel: %+v", result.Sel)
	}
}

func TestIpmiReplayFailures(t *testing.T) {
	reader := newIpmiReader(24 * time.Hour)
	result := collectIpmiReplay(t, reader, "failures.json")
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}

	expected := map[string]string{
		"Inlet Temp":    "warning",  // 43 > 40 (upper non-critical)
		"CPU1 Temp":     "ok",       //
		"Fan1":          "critical", // 0 RPM < 600 (lower critical)
		"Fan2":          "ok",       //
		"PS1 Status":    "critical", // Power Supply Failure detected
		"PS2 Status":    "ok",       //
		"PS Redundancy": "critical", // Redundancy Lost
		"Intrusion":     "critical", // General Chassis Intrusion
		"Drive 0":       "critical", // Drive Fault
		"ECC Memory":    "warning",  // Correctable ECC
	}
	for name, state := range expected {
		sensor := ipmiSensorByName(t, result, name)
		if sensor.State != state {
			t.Errorf("sensor %s: expected %s, got %s (%v)", name, state, sensor.State, sensor.States)
		}
	}
	if s := ipmiSensorByName(t, result, "Inlet Temp"); s.Status != "unc" {
		t.Errorf("expected status unc, got %s", s.Status)
	}
	if s := ipmiSensorByName(t, result, "PS1 Status"); len(s.States) != 2 || s.States[1] != "Power Supply Failure detected" {
		t.Errorf("unexpected states: %v", s.States)
	}

	// The simulator has no clock (pre-init timestamps), so the entries of the first read are old
	if result.Sel == nil || result.Sel.Entries != 15 || len(result.Sel.Events) != 0 {
		t.Fatalf("unexpected sel: %+v", result.Sel)
	}
	// Entries which appear later are new
	for _, entry := range reader.sel {
		entry.firstSeen = time.Now()
	}
	result = collectIpmiReplay(t, reader, "failures.json")
	descriptions := map[string]string{}
	for _, event := range result.Sel.Events {
		descriptions[event.Sensor+": "+event.Description] = event.Severity
		if !event.Asserted || event.Timestamp != 0 {
			t.Errorf("unexpected event: %+v", event)
		}
	}
	for description, severity := range map[string]string{
		"PS1 Status: Power Supply Failure detected":                    "Critical",
		"PS Redundancy: Redundancy Lost":                               "Critical",
		"Fan1: Lower Critical - going low":                             "Critical",
		"Inlet Temp: Upper Non-critical - going high":                  "Warning",
		"ECC Memory: Correctable ECC / other correctable memory error": "Warning",
	} {
		if descriptions[description] != severity {
			t.Errorf("event %s: expected %s, got %q", description, severity, descriptions[description])
		}
	}
	// Deassertions (e.g. the end of the power supply failure) and states like "Presence detected" are not reported
	if len(result.Sel.Events) != 8 {
		t.Errorf("expected 8 events, got %d: %v", len(result.Sel.Events), descriptions)
	}
	// Newest first
	if result.Sel.Events[0].ID < result.Sel.Events[len(result.Sel.Events)-1].ID {
		t.Errorf("events are not sorted: %d, %d", result.Sel.Events[0].ID, result.Sel.Events[len(result.Sel.Events)-1].ID)
	}
}

func TestIpmiSelWindow(t *testing.T) {
	reader := newIpmiReader(time.Hour)
	reader.selPopulated = true
	now := time.Now()
	reader.sel = map[uint16]*ipmiSelCacheEntry{
		1: {event: &resultIpmiSelEvent{ID: 1, Severity: "Critical", Timestamp: now.Add(-2 * time.Hour).Unix()}},
		2: {event: &resultIpmiSelEvent{ID: 2, Severity: "Critical", Timestamp: now.Add(-30 * time.Minute).Unix()}},
		3: {event: &resultIpmiSelEvent{ID: 3, Severity: "OK", Timestamp: now.Unix()}},
		4: {event: &resultIpmiSelEvent{ID: 4, Severity: "Warning"}, firstSeen: now},
	}
	reader.selOrder = []uint16{1, 2, 3, 4}
	var events []uint16
	for _, event := range reader.selEventsInWindow(now) {
		events = append(events, event.ID)
	}
	if len(events) != 2 || events[0] != 4 || events[1] != 2 {
		t.Errorf("unexpected events: %v", events)
	}
}

func TestIpmiDiscreteUndefinedBits(t *testing.T) {
	// VBAT of a Supermicro H11DSi: 0x04ff, only offset 2 (battery presence detected) is defined
	sensor := &types.Sensor{EventReadingType: types.EventReadingTypeSensorSpecific, SensorType: types.SensorTypeBattery}
	sensor.Discrete.ActiveStates = types.Mask_DiscreteEvent{}
	sensor.Discrete.ActiveStates.State_2 = true
	states := &sensor.Discrete.ActiveStates
	states.State_8, states.State_9, states.State_10, states.State_11, states.State_12, states.State_13, states.State_14 = true, true, true, true, true, true, true
	result := &resultIpmiSensor{}
	readIpmiDiscreteSensor(sensor, result)
	if result.State != "ok" || len(result.States) != 1 || result.States[0] != "battery presence detected" {
		t.Errorf("unexpected result: %+v", result)
	}
}

// Recordings of two Supermicro H11DSi-NT (AMD EPYC) with partially populated DIMM slots and fans
func TestIpmiReplaySupermicro(t *testing.T) {
	// ipmitool reports the firmware 1.52
	reader := newIpmiReader(time.Hour)
	if result := collectIpmiReplay(t, reader, "supermicro-h11dsi-a.json"); result.Device.FirmwareRevision != "1.52" {
		t.Errorf("unexpected firmware revision %s", result.Device.FirmwareRevision)
	}

	for name, events := range map[string]int{"supermicro-h11dsi-a.json": 3, "supermicro-h11dsi-b.json": 2} {
		t.Run(name, func(t *testing.T) {
			// A large window, so the entries of the recordings (2024 - 2026) stay within the window
			reader := newIpmiReader(50 * 365 * 24 * time.Hour)
			result := collectIpmiReplay(t, reader, name)
			if len(result.Errors) != 0 || result.Device.ManufacturerID != 10876 || result.Device.ProductID != 2404 {
				t.Fatalf("unexpected result: %+v %v", result.Device, result.Errors)
			}

			states := map[string]int{}
			for _, sensor := range result.Sensors {
				states[sensor.State]++
			}
			// 15 sensors of empty DIMM slots and fan headers have no reading
			if len(result.Sensors) != 56 || states["na"] != 15 || states["ok"] != 41 {
				t.Errorf("unexpected sensor states: %v of %d sensors", states, len(result.Sensors))
			}
			if s := ipmiSensorByName(t, result, "P1-DIMMA1 Temp"); s.State != "na" || s.Reading != nil {
				t.Errorf("unexpected empty DIMM slot: %+v", s)
			}
			// VBAT reports 0x04ff, only "battery presence detected" is defined
			if s := ipmiSensorByName(t, result, "VBAT"); s.State != "ok" || len(s.States) != 1 || s.States[0] != "battery presence detected" {
				t.Errorf("unexpected battery: %+v", s)
			}
			fan := ipmiSensorByName(t, result, "FAN1")
			if fan.Thresholds == nil || *fan.Thresholds.LowerNonRecoverable != 300 || *fan.Thresholds.LowerCritical != 500 ||
				*fan.Thresholds.LowerNonCritical != 700 || *fan.Thresholds.UpperNonRecoverable != 25500 {
				t.Errorf("unexpected fan thresholds: %+v", fan.Thresholds)
			}
			if v := ipmiSensorByName(t, result, "VDD_5_DUAL"); *v.Reading != 5.02 && *v.Reading != 4.954 {
				t.Errorf("reading not rounded: %v", *v.Reading)
			}

			// Correctable ECC errors of the BIOS (no sensor) and a power supply failure, the end of the failure and an OEM entry are not reported
			if result.Sel == nil || len(result.Sel.Events) != events {
				t.Fatalf("expected %d events, got %+v", events, result.Sel)
			}
			for _, event := range result.Sel.Events {
				if event.Timestamp == 0 || !event.Asserted {
					t.Errorf("unexpected event: %+v", event)
				}
				switch event.SensorType {
				case "Memory":
					if event.Severity != "Warning" || event.Sensor != "" {
						t.Errorf("unexpected memory event: %+v", event)
					}
				case "Power Supply":
					if event.Severity != "Critical" || event.Sensor != "PS2 Status" || event.Description != "Power Supply Failure detected" {
						t.Errorf("unexpected power supply event: %+v", event)
					}
				default:
					t.Errorf("unexpected event: %+v", event)
				}
			}
		})
	}
}

// Recordings which must not be published (e.g. dumps of other companies) are tested with rules instead of expected values:
// OITC_IPMI_PRIVATE_DUMPS=/path/to/dumps go test ./checks -run IpmiReplayPrivate
func TestIpmiReplayPrivateDumps(t *testing.T) {
	dir := os.Getenv("OITC_IPMI_PRIVATE_DUMPS")
	if dir == "" {
		t.Skip("OITC_IPMI_PRIVATE_DUMPS is not set")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Skipf("no dumps found in %s", dir)
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var dump struct {
				Recorded struct {
					Sensors []struct {
						Number      string `json:"number"`
						Reading     string `json:"reading"`
						Threshold   bool   `json:"threshold"`
						GeneratorID string `json:"generator_id"`
					} `json:"sensors"`
				} `json:"recorded"`
			}
			if err := json.Unmarshal(data, &dump); err != nil {
				t.Fatal(err)
			}

			reader := newIpmiReader(50 * 365 * 24 * time.Hour)
			result := collectIpmiReplay(t, reader, file)
			if len(result.Errors) != 0 || len(result.Sensors) == 0 {
				t.Fatalf("errors: %v, %d sensors", result.Errors, len(result.Sensors))
			}

			states := map[string]int{}
			readings := map[uint8]float64{}
			for _, sensor := range result.Sensors {
				states[sensor.State]++
				if ipmiStateOrder[sensor.State] == 0 && sensor.State != "na" || sensor.State == "unknown" {
					t.Errorf("sensor %s: invalid state %s %s", sensor.Name, sensor.State, sensor.Error)
				}
				// Sensors of the system software (e.g. the BIOS) can not be read
				if sensor.Owner&0x01 == 0x01 && sensor.State != "na" {
					t.Errorf("sensor %s of the system software %#02x has a state: %s", sensor.Name, sensor.Owner, sensor.State)
				}
				if sensor.Reading != nil {
					if sensor.Unit == "" {
						t.Errorf("sensor %s: reading without unit", sensor.Name)
					}
					if sensor.Owner == 0x20 {
						readings[sensor.Number] = *sensor.Reading
					}
				}
			}

			// The readings of the BMC sensors match the readings of go-ipmi in the dump. go-ipmi reads every sensor twice,
			// the replay answers with the first reading, so the values can differ slightly (e.g. one step of a fan).
			// Wrong conversion factors differ by orders of magnitude.
			for _, recorded := range dump.Recorded.Sensors {
				if recorded.GeneratorID != "0x0020" || !recorded.Threshold || recorded.Reading == "N/A" {
					continue
				}
				number, _ := strconv.ParseUint(strings.TrimPrefix(recorded.Number, "0x"), 16, 8)
				expected, _ := strconv.ParseFloat(recorded.Reading, 64)
				if actual, ok := readings[uint8(number)]; !ok || math.Abs(actual-expected) > math.Max(0.001, math.Abs(expected)*0.05) {
					t.Errorf("sensor %s: expected reading %v, got %v (%t)", recorded.Number, expected, actual, ok)
				}
			}

			if result.Sel == nil {
				t.Fatal("sel missing")
			}
			for _, event := range result.Sel.Events {
				if !event.Asserted || (event.Severity != "Warning" && event.Severity != "Critical") {
					t.Errorf("unexpected event: %+v", event)
				}
			}
			t.Logf("%d sensors %v, %d sel entries, %d events", len(result.Sensors), states, result.Sel.Entries, len(result.Sel.Events))
		})
	}
}

func TestIpmiSoftwareOwnedSensor(t *testing.T) {
	// Sensors of the system software (e.g. the BIOS with software id 0x58, owner 0xb1) are skipped without a command
	sdr := &types.SDR{
		RecordHeader: &types.SDRHeader{RecordType: types.SDRRecordTypeCompactSensor},
		Compact: &types.SDRCompact{
			GeneratorID:            types.GeneratorID(0x00b1),
			SensorNumber:           0x01,
			SensorType:             types.SensorTypeMemory,
			SensorEventReadingType: types.EventReadingTypeSensorSpecific,
			IDStringBytes:          []byte("ECC Corr Err"),
		},
	}
	result := readIpmiSensor(context.Background(), nil, sdr)
	if result.State != "na" || result.Owner != 0xb1 || result.Name != "ECC Corr Err" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestIpmiAbsentStates(t *testing.T) {
	// Entity Absent (e.g. the empty second CPU socket of a Dell server) and Device Absent are not a problem
	for _, test := range []struct {
		readingType types.EventReadingType
		sensorType  types.SensorType
		state       string
	}{
		{types.EventReadingTypeSensorSpecific, types.SensorTypeEntityPresence, "Entity Absent"},
		{types.EventReadingTypeDevicePresent, types.SensorTypePowerSupply, "Device Removed / Device Absent"},
	} {
		sensor := &types.Sensor{EventReadingType: test.readingType, SensorType: test.sensorType}
		if test.readingType == types.EventReadingTypeDevicePresent {
			sensor.Discrete.ActiveStates.State_0 = true
		} else {
			sensor.Discrete.ActiveStates.State_1 = true
		}
		result := &resultIpmiSensor{}
		readIpmiDiscreteSensor(sensor, result)
		if result.State != "ok" || len(result.States) != 1 || result.States[0] != test.state {
			t.Errorf("unexpected result: %+v", result)
		}
	}
}
