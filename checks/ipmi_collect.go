package checks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/bougou/go-ipmi/pkg/client"
	"github.com/bougou/go-ipmi/pkg/types"
)

const (
	// The SDR repository is read again after this time or if it was changed
	ipmiSDRCacheTime = time.Hour
	// SEL timestamps below this value are relative to the initialization of the BMC (IPMI 2.0, 37.1)
	ipmiPreInitTimestamp = 0x20000000
	// Maximum number of SEL entries in the result
	ipmiMaxSelEvents = 100
)

type resultIpmiDevice struct {
	ManufacturerID   uint32 `json:"manufacturer_id"`
	Manufacturer     string `json:"manufacturer"`
	ProductID        uint16 `json:"product_id"`
	FirmwareRevision string `json:"firmware_revision"`
	IPMIVersion      string `json:"ipmi_version"`
}

type resultIpmiChassis struct {
	PowerOn           bool `json:"power_on"`
	PowerOverload     bool `json:"power_overload"`
	PowerInterlock    bool `json:"power_interlock"`
	MainPowerFault    bool `json:"main_power_fault"`
	PowerControlFault bool `json:"power_control_fault"`
	CoolingFault      bool `json:"cooling_fault"`
	DriveFault        bool `json:"drive_fault"`
	Intrusion         bool `json:"intrusion"`
}

type resultIpmiThresholds struct {
	LowerNonRecoverable *float64 `json:"lower_non_recoverable,omitempty"`
	LowerCritical       *float64 `json:"lower_critical,omitempty"`
	LowerNonCritical    *float64 `json:"lower_non_critical,omitempty"`
	UpperNonCritical    *float64 `json:"upper_non_critical,omitempty"`
	UpperCritical       *float64 `json:"upper_critical,omitempty"`
	UpperNonRecoverable *float64 `json:"upper_non_recoverable,omitempty"`
}

type resultIpmiSensor struct {
	Name   string `json:"name"`
	Number uint8  `json:"number"`
	Owner  uint8  `json:"owner"`  // IPMB address of the controller, e.g. 0x20 for the BMC
	Type   string `json:"type"`   // e.g.: Temperature, Fan, Voltage, Power Supply
	Entity string `json:"entity"` // e.g.: processor, power supply
	// ok, warning or critical. na if the sensor has no reading (e.g. an empty DIMM slot), unknown if the reading failed.
	State string `json:"state"`
	// Analog sensors: the reading, the unit and the thresholds of the BMC
	Reading    *float64              `json:"reading,omitempty"`
	Unit       string                `json:"unit,omitempty"`       // e.g.: degrees C, RPM, Volts, Watts
	Status     string                `json:"status,omitempty"`     // Threshold status: ok, lnc, lcr, lnr, unc, ucr or unr
	Thresholds *resultIpmiThresholds `json:"thresholds,omitempty"` // Only readable thresholds
	// Discrete sensors: the active states, e.g. "Presence detected", "Power Supply Failure detected"
	States []string `json:"states,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type resultIpmiSelEvent struct {
	ID          uint16 `json:"id"`
	Timestamp   int64  `json:"timestamp"` // Unix timestamp, 0 if the BMC did not know the time (pre-init timestamp)
	Sensor      string `json:"sensor"`    // Name of the sensor, empty if unknown
	SensorType  string `json:"sensor_type"`
	Description string `json:"description"`
	Asserted    bool   `json:"asserted"`
	// OK, Warning or Critical. Deassertions (the end of a condition) are OK.
	Severity string `json:"severity"`
}

type resultIpmiSel struct {
	Entries     int   `json:"entries"`
	FreeBytes   int   `json:"free_bytes"`
	PercentUsed int   `json:"percent_used"` // The SEL has 16 bytes per entry
	Overflow    bool  `json:"overflow"`     // The SEL is full and events got dropped
	LastAdd     int64 `json:"last_add"`     // Unix timestamp of the last added entry, 0 if unknown
	Window      int64 `json:"window"`       // Seconds
	// Warning and critical entries within the window, newest first
	Events []*resultIpmiSelEvent `json:"events"`
}

type resultIpmi struct {
	CollectedAt int64               `json:"collected_at"`
	Interval    int64               `json:"interval"` // Seconds between the collections
	Device      *resultIpmiDevice   `json:"device"`
	Chassis     *resultIpmiChassis  `json:"chassis,omitempty"`
	Sensors     []*resultIpmiSensor `json:"sensors"`
	Sel         *resultIpmiSel      `json:"sel,omitempty"`
	Errors      []string            `json:"errors,omitempty"` // Parts which could not be read, e.g. the SEL
}

// ipmiSelCacheEntry is a SEL entry which was read before. The entries of the SEL do not change, so only new entries are read.
type ipmiSelCacheEntry struct {
	event *resultIpmiSelEvent
	// Time when the entry was read the first time, used for pre-init timestamps
	firstSeen time.Time
}

// ipmiReader reads the sensors and the SEL of a BMC. The SDR repository and the SEL are cached between the collections.
type ipmiReader struct {
	selWindow time.Duration

	sdrs          []*types.SDR
	sdrTimestamp  time.Time
	sdrRepoChange time.Time // Most recent addition or erase of the SDR repository

	sel          map[uint16]*ipmiSelCacheEntry
	selOrder     []uint16
	selAddition  time.Time
	selErase     time.Time
	selLastID    uint16
	selPopulated bool
	// The SEL was read successfully once. Entries without timestamp of the first read are old,
	// entries without timestamp which appear later (e.g. after the SEL was cleared) are new.
	selInitialized bool
}

func newIpmiReader(selWindow time.Duration) *ipmiReader {
	return &ipmiReader{selWindow: selWindow, sel: map[uint16]*ipmiSelCacheEntry{}}
}

// collect reads the BMC. Only the device id is required, the other parts are reported as error.
func (r *ipmiReader) collect(ctx context.Context, c *client.Client) (*resultIpmi, error) {
	result := &resultIpmi{CollectedAt: time.Now().Unix(), Sensors: []*resultIpmiSensor{}}

	deviceID, err := c.GetDeviceID(ctx)
	if err != nil {
		return nil, fmt.Errorf("get device id: %w", err)
	}
	result.Device = &resultIpmiDevice{
		ManufacturerID: deviceID.ManufacturerID,
		Manufacturer:   types.OEM(deviceID.ManufacturerID).String(),
		ProductID:      deviceID.ProductID,
		// go-ipmi decodes the BCD minor revision, e.g. 0x52 => 52 (firmware 1.52)
		FirmwareRevision: fmt.Sprintf("%d.%02d", deviceID.MajorFirmwareRevision, deviceID.MinorFirmwareRevision),
		IPMIVersion:      fmt.Sprintf("%d.%d", deviceID.MajorIPMIVersion, deviceID.MinorIPMIVersion),
	}

	if chassis, err := c.GetChassisStatus(ctx); err == nil {
		result.Chassis = &resultIpmiChassis{
			PowerOn:           chassis.PowerIsOn,
			PowerOverload:     chassis.PowerOverload,
			PowerInterlock:    chassis.InterLock,
			MainPowerFault:    chassis.PowerFault,
			PowerControlFault: chassis.PowerControlFault,
			CoolingFault:      chassis.CollingFanFault,
			DriveFault:        chassis.DriveFault,
			Intrusion:         chassis.ChassisIntrusionActive,
		}
	} else if !ipmiIsUnsupported(err) {
		result.Errors = append(result.Errors, fmt.Sprintf("chassis status: %s", err))
	}

	if err := r.readSDRs(ctx, c); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("sdr repository: %s", err))
	}
	for _, sdr := range r.sdrs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		result.Sensors = append(result.Sensors, readIpmiSensor(ctx, c, sdr))
	}

	sel, err := r.readSel(ctx, c)
	if err != nil {
		if !ipmiIsUnsupported(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("sel: %s", err))
		}
	} else {
		result.Sel = sel
	}
	return result, nil
}

// ipmiIsUnsupported returns true for completion codes of commands which are not supported by the BMC
func ipmiIsUnsupported(err error) bool {
	var respErr *types.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	code := respErr.CompletionCode()
	return code == types.CodeInvalidCommand || code == types.CodeIllegalCommand || code == types.CodeRequestedDataNotPresent
}

// readSDRs reads the sensor records of the SDR repository, if the cache is expired or the repository was changed
func (r *ipmiReader) readSDRs(ctx context.Context, c *client.Client) error {
	var change time.Time
	if info, err := c.GetSDRRepoInfo(ctx); err == nil {
		change = info.MostRecentAdditionTime
		if info.MostRecentEraseTime.After(change) {
			change = info.MostRecentEraseTime
		}
	}
	if r.sdrs != nil && time.Since(r.sdrTimestamp) < ipmiSDRCacheTime && change.Equal(r.sdrRepoChange) {
		return nil
	}

	sdrs, err := c.GetSDRsRaw(ctx, types.SDRRecordTypeFullSensor, types.SDRRecordTypeCompactSensor)
	if err != nil {
		return err
	}
	r.sdrs = sdrs
	r.sdrTimestamp = time.Now()
	r.sdrRepoChange = change
	return nil
}

// ipmiValue rounds a converted reading to 3 decimals, e.g. 5.0200000000000005 => 5.02
func ipmiValue(value float64) *float64 {
	value = math.Round(value*1000) / 1000
	return &value
}

// readIpmiSensor reads a sensor. In contrast to client.GetSensors, an error only affects this sensor.
func readIpmiSensor(ctx context.Context, c *client.Client, sdr *types.SDR) *resultIpmiSensor {
	sensor := &types.Sensor{SDRRecordType: sdr.RecordHeader.RecordType, HasAnalogReading: sdr.HasAnalogReading()}
	switch sdr.RecordHeader.RecordType {
	case types.SDRRecordTypeFullSensor:
		full := sdr.Full
		sensor.GeneratorID = full.GeneratorID
		sensor.Number = uint8(full.SensorNumber)
		sensor.Name = strings.TrimSpace(string(full.IDStringBytes))
		sensor.SensorUnit = full.SensorUnit
		sensor.SensorType = full.SensorType
		sensor.EventReadingType = full.SensorEventReadingType
		sensor.EntityID = full.SensorEntityID
		sensor.EntityInstance = full.SensorEntityInstance
		sensor.Threshold.LinearizationFunc = full.LinearizationFunc
		sensor.Threshold.ReadingFactors = full.ReadingFactors
	case types.SDRRecordTypeCompactSensor:
		compact := sdr.Compact
		sensor.GeneratorID = compact.GeneratorID
		sensor.Number = uint8(compact.SensorNumber)
		sensor.Name = strings.TrimSpace(string(compact.IDStringBytes))
		sensor.SensorUnit = compact.SensorUnit
		sensor.SensorType = compact.SensorType
		sensor.EventReadingType = compact.SensorEventReadingType
		sensor.EntityID = compact.SensorEntityID
		sensor.EntityInstance = compact.SensorEntityInstance
	}

	result := &resultIpmiSensor{
		Name:   strings.TrimRight(sensor.Name, "\x00"),
		Number: sensor.Number,
		Owner:  sensor.GeneratorID.OwnerID(),
		Type:   sensor.SensorType.String(),
		Entity: sensor.EntityID.String(),
		State:  "na",
	}

	// Sensors owned by system software (e.g. the BIOS of Dell servers) can not be read,
	// their records are only used to describe the events of the SEL
	if sensor.GeneratorID.OwnerIsSystemSoftware() {
		return result
	}

	// Sensors of other controllers (e.g. the management engine) are read through the BMC
	ctx = client.WithCommandContext(ctx, (&client.CommandContext{}).
		WithResponderAddr(sensor.GeneratorID.OwnerID()).
		WithResponderLUN(sensor.GeneratorID.LUN()))

	reading, err := c.GetSensorReading(ctx, sensor.Number)
	if err != nil {
		if ipmiIsUnsupported(err) || ipmiIsCompletionCode(err, types.CodeDestinationUnavailable) {
			// The sensor is not present (e.g. an empty DIMM slot) or its controller is not available
			return result
		}
		result.State = "unknown"
		result.Error = err.Error()
		return result
	}
	if reading.SensorScanningDisabled || reading.ReadingUnavailable {
		return result
	}
	sensor.Raw = reading.Reading
	sensor.ReadingAvailable = true
	sensor.Threshold.ThresholdStatus = reading.ThresholdStatus()
	sensor.Discrete.ActiveStates = reading.ActiveStates

	if sensor.EventReadingType.IsThreshold() && sensor.SensorUnit.IsAnalog() {
		readIpmiThresholdSensor(ctx, c, sdr, sensor, result)
	} else {
		readIpmiDiscreteSensor(sensor, result)
	}
	return result
}

func readIpmiThresholdSensor(ctx context.Context, c *client.Client, sdr *types.SDR, sensor *types.Sensor, result *resultIpmiSensor) {
	// Non-linear sensors require the reading factors of the current reading
	if sdr.RecordHeader.RecordType == types.SDRRecordTypeFullSensor && sensor.Threshold.LinearizationFunc.IsNonLinear() {
		factors, err := c.GetSensorReadingFactors(ctx, sensor.Number, sensor.Raw)
		if err != nil {
			result.State = "unknown"
			result.Error = err.Error()
			return
		}
		sensor.Threshold.ReadingFactors = factors.ReadingFactors
	}

	result.Reading = ipmiValue(sensor.ConvertReading(sensor.Raw))
	result.Unit = sensor.SensorUnit.String()
	result.Status = string(sensor.Threshold.ThresholdStatus)
	switch sensor.Threshold.ThresholdStatus {
	case types.SensorThresholdStatus_OK:
		result.State = "ok"
	case types.SensorThresholdStatus_LNC, types.SensorThresholdStatus_UNC:
		result.State = "warning"
	default:
		result.State = "critical"
	}

	// Compact sensors have no thresholds
	if sdr.RecordHeader.RecordType != types.SDRRecordTypeFullSensor {
		return
	}
	thresholds, err := c.GetSensorThresholds(ctx, sensor.Number)
	if err != nil {
		return
	}
	t := &resultIpmiThresholds{}
	if thresholds.LNR_Readable {
		t.LowerNonRecoverable = ipmiValue(sensor.ConvertReading(thresholds.LNR_Raw))
	}
	if thresholds.LCR_Readable {
		t.LowerCritical = ipmiValue(sensor.ConvertReading(thresholds.LCR_Raw))
	}
	if thresholds.LNC_Readable {
		t.LowerNonCritical = ipmiValue(sensor.ConvertReading(thresholds.LNC_Raw))
	}
	if thresholds.UNC_Readable {
		t.UpperNonCritical = ipmiValue(sensor.ConvertReading(thresholds.UNC_Raw))
	}
	if thresholds.UCR_Readable {
		t.UpperCritical = ipmiValue(sensor.ConvertReading(thresholds.UCR_Raw))
	}
	if thresholds.UNR_Readable {
		t.UpperNonRecoverable = ipmiValue(sensor.ConvertReading(thresholds.UNR_Raw))
	}
	result.Thresholds = t
}

func ipmiIsCompletionCode(err error, code types.CompletionCode) bool {
	var respErr *types.ResponseError
	return errors.As(err, &respErr) && respErr.CompletionCode() == code
}

// ipmiAbsentState returns true for the states of a missing entity. go-ipmi rates them as critical,
// but they are reported for empty slots, e.g. the second CPU socket of a Dell server.
func ipmiAbsentState(eventReadingType types.EventReadingType, sensorType types.SensorType, offset uint8) bool {
	if sensorType == types.SensorTypeEntityPresence && offset == 1 {
		// Entity Absent
		return true
	}
	// Device Removed / Device Absent
	return eventReadingType == types.EventReadingTypeDevicePresent && offset == 0
}

// readIpmiDiscreteSensor evaluates the active states of a discrete sensor with the severities of the IPMI specification
func readIpmiDiscreteSensor(sensor *types.Sensor, result *resultIpmiSensor) {
	result.State = "ok"
	result.States = []string{}
	for _, offset := range sensor.Discrete.ActiveStates.TrueEvents() {
		event := sensor.EventReadingType.EventForOffset(sensor.SensorType, offset)
		if event == nil {
			// Some BMCs set undefined bits (e.g. 0x04ff of a battery sensor)
			continue
		}
		result.States = append(result.States, event.EventName)
		if ipmiAbsentState(sensor.EventReadingType, sensor.SensorType, offset) {
			continue
		}
		severity := ipmiSeverityState(sensor.EventReadingType.EventSeverity(sensor.SensorType, types.EventData{EventData1: offset}, false))
		result.State = worseIpmiState(result.State, severity)
	}
}

// ipmiSeverityState converts the severity of an event to ok, warning or critical
func ipmiSeverityState(severity types.EventSeverity) string {
	switch severity {
	case types.EventSeverityCritical:
		return "critical"
	case types.EventSeverityWarning, types.EventSeverityDegraded, types.EventSeverityNonFatal:
		return "warning"
	default:
		return "ok"
	}
}

var ipmiStateOrder = map[string]int{"na": 0, "ok": 1, "unknown": 2, "warning": 3, "critical": 4}

func worseIpmiState(a, b string) string {
	if ipmiStateOrder[b] > ipmiStateOrder[a] {
		return b
	}
	return a
}

// readSel reads the new entries of the SEL and returns the warnings and critical entries within the window
func (r *ipmiReader) readSel(ctx context.Context, c *client.Client) (*resultIpmiSel, error) {
	info, err := c.GetSELInfo(ctx)
	if err != nil {
		return nil, err
	}
	result := &resultIpmiSel{
		Entries:   int(info.Entries),
		FreeBytes: int(info.FreeBytes),
		Overflow:  info.OperationSupport.Overflow,
		Window:    int64(r.selWindow.Seconds()),
		Events:    []*resultIpmiSelEvent{},
	}
	if total := int(info.Entries)*16 + int(info.FreeBytes); total > 0 {
		result.PercentUsed = int(info.Entries) * 16 * 100 / total
	}
	if ipmiValidTimestamp(info.RecentAdditionTime) {
		result.LastAdd = info.RecentAdditionTime.Unix()
	}

	if info.Entries == 0 {
		r.resetSel()
	} else if !r.selPopulated || !info.RecentEraseTime.Equal(r.selErase) || len(r.sel) > int(info.Entries) {
		// First read or the SEL was cleared: read all entries
		r.resetSel()
		if err := r.readSelEntries(ctx, c, 0, !r.selInitialized); err != nil {
			r.resetSel()
			return nil, err
		}
	} else if !info.RecentAdditionTime.Equal(r.selAddition) {
		// New entries: continue with the last known entry
		if err := r.readSelEntries(ctx, c, r.selLastID, false); err != nil {
			r.resetSel()
			return nil, err
		}
	}
	r.selAddition = info.RecentAdditionTime
	r.selErase = info.RecentEraseTime
	r.selPopulated = true
	r.selInitialized = true

	result.Events = r.selEventsInWindow(time.Now())
	return result, nil
}

// selEventsInWindow returns the warnings and critical entries within the window, newest first.
// Entries without timestamp (pre-init) use the time when the agent read them the first time.
func (r *ipmiReader) selEventsInWindow(now time.Time) []*resultIpmiSelEvent {
	events := []*resultIpmiSelEvent{}
	for i := len(r.selOrder) - 1; i >= 0 && len(events) < ipmiMaxSelEvents; i-- {
		entry := r.sel[r.selOrder[i]]
		if entry.event.Severity == "OK" {
			continue
		}
		timestamp := entry.firstSeen
		if entry.event.Timestamp > 0 {
			timestamp = time.Unix(entry.event.Timestamp, 0)
		}
		if now.Sub(timestamp) > r.selWindow {
			continue
		}
		events = append(events, entry.event)
	}
	return events
}

func (r *ipmiReader) resetSel() {
	r.sel = map[uint16]*ipmiSelCacheEntry{}
	r.selOrder = nil
	r.selLastID = 0
	r.selPopulated = false
}

// readSelEntries reads the entries of the SEL starting with the given record id.
// Entries with pre-init timestamps of the first read are treated as old entries.
func (r *ipmiReader) readSelEntries(ctx context.Context, c *client.Client, recordID uint16, initial bool) error {
	firstSeen := time.Now()
	if initial {
		firstSeen = time.Time{}
	}
	sdrNames := r.sensorNames()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		entry, err := c.GetSELEntry(ctx, 0, recordID)
		if err != nil {
			return err
		}
		sel, err := types.ParseSEL(entry.Data)
		if err != nil {
			return err
		}
		if _, ok := r.sel[sel.RecordID]; !ok {
			r.sel[sel.RecordID] = &ipmiSelCacheEntry{event: ipmiSelEvent(sel, sdrNames), firstSeen: firstSeen}
			r.selOrder = append(r.selOrder, sel.RecordID)
		}
		r.selLastID = sel.RecordID
		if entry.NextRecordID == 0xffff || entry.NextRecordID == recordID {
			return nil
		}
		recordID = entry.NextRecordID
	}
}

type ipmiSensorKey struct {
	owner  uint8
	number uint8
}

// sensorNames returns the names of the sensors of the cached SDRs
func (r *ipmiReader) sensorNames() map[ipmiSensorKey]string {
	names := map[ipmiSensorKey]string{}
	for _, sdr := range r.sdrs {
		switch sdr.RecordHeader.RecordType {
		case types.SDRRecordTypeFullSensor:
			names[ipmiSensorKey{sdr.Full.GeneratorID.OwnerID(), uint8(sdr.Full.SensorNumber)}] = strings.TrimSpace(string(sdr.Full.IDStringBytes))
		case types.SDRRecordTypeCompactSensor:
			names[ipmiSensorKey{sdr.Compact.GeneratorID.OwnerID(), uint8(sdr.Compact.SensorNumber)}] = strings.TrimSpace(string(sdr.Compact.IDStringBytes))
		}
	}
	return names
}

func ipmiValidTimestamp(t time.Time) bool {
	unix := t.Unix()
	return unix >= ipmiPreInitTimestamp && unix != 0xffffffff
}

// ipmiSelEvent converts a SEL entry. Deassertions (the end of a condition) and OEM entries are OK.
func ipmiSelEvent(sel *types.SEL, sensorNames map[ipmiSensorKey]string) *resultIpmiSelEvent {
	event := &resultIpmiSelEvent{ID: sel.RecordID, Severity: "OK"}
	switch {
	case sel.Standard != nil:
		standard := sel.Standard
		if ipmiValidTimestamp(standard.Timestamp) {
			event.Timestamp = standard.Timestamp.Unix()
		}
		event.Sensor = sensorNames[ipmiSensorKey{standard.GeneratorID.OwnerID(), uint8(standard.SensorNumber)}]
		event.SensorType = standard.SensorType.String()
		event.Asserted = !bool(standard.EventDir)
		event.Description = standard.EventReadingType.EventString(standard.SensorType, standard.EventData)
		if event.Description == "" {
			event.Description = fmt.Sprintf("Event offset %#02x", standard.EventData.EventReadingOffset())
		}
		if event.Asserted {
			switch ipmiSeverityState(standard.EventReadingType.EventSeverity(standard.SensorType, standard.EventData, standard.EventDir)) {
			case "critical":
				event.Severity = "Critical"
			case "warning":
				event.Severity = "Warning"
			}
		}
	case sel.OEMTimestamped != nil:
		if ipmiValidTimestamp(sel.OEMTimestamped.Timestamp) {
			event.Timestamp = sel.OEMTimestamped.Timestamp.Unix()
		}
		event.SensorType = "OEM"
		event.Description = fmt.Sprintf("OEM record %#02x", uint8(sel.RecordType))
	default:
		event.SensorType = "OEM"
		event.Description = fmt.Sprintf("OEM record %#02x", uint8(sel.RecordType))
	}
	return event
}
