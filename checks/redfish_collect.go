package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const (
	// Maximum number of event log entries in the result, the newest entries are kept
	redfishMaxEventlogEntries = 50
	redfishMaxMessageLength   = 300
)

type resultRedfishStatus struct {
	State        string   `json:"state"`  // e.g.: Enabled, Absent, StandbyOffline
	Health       string   `json:"health"` // OK, Warning, Critical or empty
	HealthRollup string   `json:"health_rollup,omitempty"`
	Conditions   []string `json:"conditions,omitempty"` // Reasons of the health, e.g.: Power supply 'PSU 1' has a predicted failure condition.
}

type resultRedfishSystem struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Manufacturer   string               `json:"manufacturer"`
	Model          string               `json:"model"`
	SerialNumber   string               `json:"serial_number"`
	BiosVersion    string               `json:"bios_version"`
	PowerState     string               `json:"power_state"` // On, Off, PoweringOn, PoweringOff
	Status         *resultRedfishStatus `json:"status"`
	Processors     *resultRedfishStatus `json:"processors"`
	ProcessorCount int64                `json:"processor_count"`
	Memory         *resultRedfishStatus `json:"memory"`
	MemoryGiB      float64              `json:"memory_gib"`
}

type resultRedfishSensor struct {
	Name            string               `json:"name"`
	Reading         *float64             `json:"reading"`
	Units           string               `json:"units"` // Cel, RPM or %
	PhysicalContext string               `json:"physical_context,omitempty"`
	UpperWarning    *float64             `json:"upper_warning,omitempty"`
	UpperCritical   *float64             `json:"upper_critical,omitempty"`
	LowerWarning    *float64             `json:"lower_warning,omitempty"`
	LowerCritical   *float64             `json:"lower_critical,omitempty"`
	Status          *resultRedfishStatus `json:"status"`
}

type resultRedfishPowerSupply struct {
	Name            string               `json:"name"`
	Model           string               `json:"model"`
	SerialNumber    string               `json:"serial_number"`
	FirmwareVersion string               `json:"firmware_version"`
	CapacityWatts   *float64             `json:"capacity_watts"`
	OutputWatts     *float64             `json:"output_watts"`
	Status          *resultRedfishStatus `json:"status"`
}

type resultRedfishRedundancy struct {
	Name   string               `json:"name"`
	Group  string               `json:"group"` // fans or power_supplies
	Mode   string               `json:"mode"`  // e.g.: N+m, Failover, NPlusM
	Status *resultRedfishStatus `json:"status"`
}

type resultRedfishChassis struct {
	ID                 string                      `json:"id"`
	Name               string                      `json:"name"`
	ChassisType        string                      `json:"chassis_type"`
	Manufacturer       string                      `json:"manufacturer"`
	Model              string                      `json:"model"`
	SerialNumber       string                      `json:"serial_number"`
	Status             *resultRedfishStatus        `json:"status"`
	Temperatures       []*resultRedfishSensor      `json:"temperatures"`
	Fans               []*resultRedfishSensor      `json:"fans"`
	PowerSupplies      []*resultRedfishPowerSupply `json:"power_supplies"`
	Redundancy         []*resultRedfishRedundancy  `json:"redundancy"`
	PowerConsumedWatts *float64                    `json:"power_consumed_watts"`
	PowerCapacityWatts *float64                    `json:"power_capacity_watts"`
}

type resultRedfishController struct {
	Name            string               `json:"name"`
	Model           string               `json:"model"`
	FirmwareVersion string               `json:"firmware_version"`
	Status          *resultRedfishStatus `json:"status"`
}

type resultRedfishDrive struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	Model            string               `json:"model"`
	SerialNumber     string               `json:"serial_number"`
	MediaType        string               `json:"media_type"` // HDD or SSD
	Protocol         string               `json:"protocol"`   // e.g.: SAS, SATA, NVMe
	CapacityBytes    int64                `json:"capacity_bytes"`
	FailurePredicted bool                 `json:"failure_predicted"`
	LifeLeftPercent  *float64             `json:"life_left_percent"` // PredictedMediaLifeLeftPercent of SSDs
	Status           *resultRedfishStatus `json:"status"`
}

type resultRedfishVolume struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	RAIDType      string               `json:"raid_type"` // e.g.: RAID1, RAID5, None
	CapacityBytes int64                `json:"capacity_bytes"`
	Status        *resultRedfishStatus `json:"status"`
}

type resultRedfishStorage struct {
	ID          string                     `json:"id"`
	Name        string                     `json:"name"`
	System      string                     `json:"system"`
	Status      *resultRedfishStatus       `json:"status"`
	Controllers []*resultRedfishController `json:"controllers"`
	Drives      []*resultRedfishDrive      `json:"drives"`
	Volumes     []*resultRedfishVolume     `json:"volumes"`
}

type resultRedfishManager struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Model           string               `json:"model"`
	FirmwareVersion string               `json:"firmware_version"`
	Status          *resultRedfishStatus `json:"status"`
}

type resultRedfishLogEntry struct {
	Created   int64  `json:"created"`
	Severity  string `json:"severity"` // Warning or Critical
	Message   string `json:"message"`
	MessageID string `json:"message_id"`
	Service   string `json:"service"` // Path of the log service
}

type resultRedfishEventlog struct {
	Window   int64                    `json:"window"`
	Services []string                 `json:"services"` // Log services which were read
	Entries  []*resultRedfishLogEntry `json:"entries"`  // Newest first
}

type resultRedfish struct {
	CollectedAt    int64   `json:"collected_at"`
	Duration       float64 `json:"duration"`
	Interval       int64   `json:"interval"`
	URL            string  `json:"url"`
	Vendor         string  `json:"vendor"`
	RedfishVersion string  `json:"redfish_version"`
	Requests       int     `json:"requests"`
	// The parts contain a list or {"error": "..."}, if the part could not be read
	Systems  interface{} `json:"systems"`
	Chassis  interface{} `json:"chassis"`
	Storage  interface{} `json:"storage"`
	Managers interface{} `json:"managers"`
	Eventlog interface{} `json:"eventlog"`
	// Problems which affect only a single resource, e.g. the thermal data of a chassis
	Warnings []string `json:"warnings"`
}

// Redfish JSON

type redfishStatusJSON struct {
	State        string `json:"State"`
	Health       string `json:"Health"`
	HealthRollup string `json:"HealthRollup"`
	Conditions   []struct {
		Message string `json:"Message"`
	} `json:"Conditions"`
}

func (s redfishStatusJSON) result() *resultRedfishStatus {
	status := &resultRedfishStatus{State: s.State, Health: s.Health, HealthRollup: s.HealthRollup}
	for _, condition := range s.Conditions {
		if condition.Message != "" {
			status.Conditions = append(status.Conditions, truncateString(condition.Message, redfishMaxMessageLength))
		}
	}
	return status
}

type redfishSystemJSON struct {
	ID               string            `json:"Id"`
	Name             string            `json:"Name"`
	Manufacturer     string            `json:"Manufacturer"`
	Model            string            `json:"Model"`
	SerialNumber     string            `json:"SerialNumber"`
	BiosVersion      string            `json:"BiosVersion"`
	PowerState       string            `json:"PowerState"`
	Status           redfishStatusJSON `json:"Status"`
	ProcessorSummary struct {
		Count  int64             `json:"Count"`
		Status redfishStatusJSON `json:"Status"`
	} `json:"ProcessorSummary"`
	MemorySummary struct {
		TotalSystemMemoryGiB float64           `json:"TotalSystemMemoryGiB"`
		Status               redfishStatusJSON `json:"Status"`
	} `json:"MemorySummary"`
	Storage     odataLink `json:"Storage"`
	LogServices odataLink `json:"LogServices"`
}

type redfishChassisJSON struct {
	ID                 string            `json:"Id"`
	Name               string            `json:"Name"`
	ChassisType        string            `json:"ChassisType"`
	Manufacturer       string            `json:"Manufacturer"`
	Model              string            `json:"Model"`
	SerialNumber       string            `json:"SerialNumber"`
	Status             redfishStatusJSON `json:"Status"`
	Thermal            odataLink         `json:"Thermal"`
	Power              odataLink         `json:"Power"`
	ThermalSubsystem   odataLink         `json:"ThermalSubsystem"`
	PowerSubsystem     odataLink         `json:"PowerSubsystem"`
	Sensors            odataLink         `json:"Sensors"`
	EnvironmentMetrics odataLink         `json:"EnvironmentMetrics"`
}

type redfishRedundancyJSON struct {
	Name           string            `json:"Name"`
	Mode           string            `json:"Mode"`
	RedundancyType string            `json:"RedundancyType"`
	Status         redfishStatusJSON `json:"Status"`
}

// Thermal and Power are deprecated, but provided by most BMCs and contain all values in a single resource
type redfishThermalJSON struct {
	Temperatures []struct {
		Name                      string            `json:"Name"`
		ReadingCelsius            *float64          `json:"ReadingCelsius"`
		UpperThresholdNonCritical *float64          `json:"UpperThresholdNonCritical"`
		UpperThresholdCritical    *float64          `json:"UpperThresholdCritical"`
		LowerThresholdNonCritical *float64          `json:"LowerThresholdNonCritical"`
		LowerThresholdCritical    *float64          `json:"LowerThresholdCritical"`
		PhysicalContext           string            `json:"PhysicalContext"`
		Status                    redfishStatusJSON `json:"Status"`
	} `json:"Temperatures"`
	Fans []struct {
		Name                      string            `json:"Name"`
		FanName                   string            `json:"FanName"` // Thermal < 1.1
		Reading                   *float64          `json:"Reading"`
		ReadingUnits              string            `json:"ReadingUnits"`
		UpperThresholdNonCritical *float64          `json:"UpperThresholdNonCritical"`
		UpperThresholdCritical    *float64          `json:"UpperThresholdCritical"`
		LowerThresholdNonCritical *float64          `json:"LowerThresholdNonCritical"`
		LowerThresholdCritical    *float64          `json:"LowerThresholdCritical"`
		PhysicalContext           string            `json:"PhysicalContext"`
		Status                    redfishStatusJSON `json:"Status"`
	} `json:"Fans"`
	Redundancy []redfishRedundancyJSON `json:"Redundancy"`
}

type redfishPowerJSON struct {
	PowerControl []struct {
		PowerConsumedWatts *float64 `json:"PowerConsumedWatts"`
		PowerCapacityWatts *float64 `json:"PowerCapacityWatts"`
	} `json:"PowerControl"`
	PowerSupplies []struct {
		Name                 string            `json:"Name"`
		Model                string            `json:"Model"`
		SerialNumber         string            `json:"SerialNumber"`
		FirmwareVersion      string            `json:"FirmwareVersion"`
		PowerCapacityWatts   *float64          `json:"PowerCapacityWatts"`
		LastPowerOutputWatts *float64          `json:"LastPowerOutputWatts"`
		Status               redfishStatusJSON `json:"Status"`
	} `json:"PowerSupplies"`
	Redundancy []redfishRedundancyJSON `json:"Redundancy"`
}

type redfishThresholdJSON struct {
	Reading *float64 `json:"Reading"`
}

type redfishSensorJSON struct {
	Name            string            `json:"Name"`
	Reading         *float64          `json:"Reading"`
	ReadingType     string            `json:"ReadingType"`
	ReadingUnits    string            `json:"ReadingUnits"`
	PhysicalContext string            `json:"PhysicalContext"`
	Status          redfishStatusJSON `json:"Status"`
	Thresholds      struct {
		UpperCaution  redfishThresholdJSON `json:"UpperCaution"`
		UpperCritical redfishThresholdJSON `json:"UpperCritical"`
		LowerCaution  redfishThresholdJSON `json:"LowerCaution"`
		LowerCritical redfishThresholdJSON `json:"LowerCritical"`
	} `json:"Thresholds"`
}

type redfishStorageJSON struct {
	ID                 string            `json:"Id"`
	Name               string            `json:"Name"`
	Status             redfishStatusJSON `json:"Status"`
	StorageControllers []struct {
		Name            string            `json:"Name"`
		Model           string            `json:"Model"`
		FirmwareVersion string            `json:"FirmwareVersion"`
		Status          redfishStatusJSON `json:"Status"`
	} `json:"StorageControllers"`
	Controllers odataLink         `json:"Controllers"` // Storage >= 1.15
	Drives      []json.RawMessage `json:"Drives"`
	Volumes     odataLink         `json:"Volumes"`
}

type redfishDriveJSON struct {
	ID                            string            `json:"Id"`
	Name                          string            `json:"Name"`
	Model                         string            `json:"Model"`
	SerialNumber                  string            `json:"SerialNumber"`
	MediaType                     string            `json:"MediaType"`
	Protocol                      string            `json:"Protocol"`
	CapacityBytes                 int64             `json:"CapacityBytes"`
	FailurePredicted              bool              `json:"FailurePredicted"`
	PredictedMediaLifeLeftPercent *float64          `json:"PredictedMediaLifeLeftPercent"`
	Status                        redfishStatusJSON `json:"Status"`
}

type redfishVolumeJSON struct {
	ID            string            `json:"Id"`
	Name          string            `json:"Name"`
	RAIDType      string            `json:"RAIDType"`
	VolumeType    string            `json:"VolumeType"` // Deprecated, e.g. Mirrored
	CapacityBytes int64             `json:"CapacityBytes"`
	Status        redfishStatusJSON `json:"Status"`
}

type redfishManagerJSON struct {
	ID              string            `json:"Id"`
	Name            string            `json:"Name"`
	Model           string            `json:"Model"`
	FirmwareVersion string            `json:"FirmwareVersion"`
	Status          redfishStatusJSON `json:"Status"`
	LogServices     odataLink         `json:"LogServices"`
}

type redfishLogServiceJSON struct {
	ODataID        string    `json:"@odata.id"`
	ID             string    `json:"Id"`
	ServiceEnabled *bool     `json:"ServiceEnabled"`
	Entries        odataLink `json:"Entries"`
}

type redfishLogEntryJSON struct {
	Created   string `json:"Created"`
	Severity  string `json:"Severity"`
	Message   string `json:"Message"`
	MessageID string `json:"MessageId"`
}

// collectRedfish reads all data of a BMC
func collectRedfish(ctx context.Context, client *redfishClient, def *config.RedfishDefinition, now time.Time) (*resultRedfish, error) {
	client.requests = 0
	client.warnings = []string{}

	root, err := client.connect(ctx)
	if err != nil {
		return nil, err
	}

	result := &resultRedfish{
		CollectedAt:    now.Unix(),
		Interval:       def.Interval,
		URL:            def.URL,
		Vendor:         root.Vendor,
		RedfishVersion: root.RedfishVersion,
	}

	var logServices []string
	systems, systemLogs, storageLinks, err := collectRedfishSystems(ctx, client, root.Systems.ID)
	if err != nil {
		result.Systems = map[string]string{"error": err.Error()}
		result.Storage = map[string]string{"error": err.Error()}
	} else {
		result.Systems = systems
		result.Storage = collectRedfishStorage(ctx, client, storageLinks)
		logServices = append(logServices, systemLogs...)
		if result.Vendor == "" && len(systems) > 0 {
			result.Vendor = systems[0].Manufacturer
		}
	}

	if chassis, err := collectRedfishChassis(ctx, client, root.Chassis.ID); err != nil {
		result.Chassis = map[string]string{"error": err.Error()}
	} else {
		result.Chassis = chassis
	}

	managers, managerLogs, err := collectRedfishManagers(ctx, client, root.Managers.ID)
	if err != nil {
		result.Managers = map[string]string{"error": err.Error()}
	} else {
		result.Managers = managers
		logServices = append(logServices, managerLogs...)
	}

	if *def.Eventlog {
		result.Eventlog = collectRedfishEventlog(ctx, client, def, logServices, now)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("the collection did not finish within %d seconds", def.Interval)
	}

	result.Duration = time.Since(now).Seconds()
	result.Requests = client.requests
	result.Warnings = client.warnings
	return result, nil
}

func collectRedfishSystems(ctx context.Context, client *redfishClient, path string) ([]*resultRedfishSystem, []string, []string, error) {
	systems := []*resultRedfishSystem{}
	var logServices, storage []string
	if path == "" {
		return systems, nil, nil, nil
	}
	members, err := client.members(ctx, path)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, member := range members {
		var system redfishSystemJSON
		if err := json.Unmarshal(member, &system); err != nil {
			client.warnings = append(client.warnings, fmt.Sprintf("system: %s", err))
			continue
		}
		systems = append(systems, &resultRedfishSystem{
			ID:             system.ID,
			Name:           system.Name,
			Manufacturer:   system.Manufacturer,
			Model:          system.Model,
			SerialNumber:   system.SerialNumber,
			BiosVersion:    system.BiosVersion,
			PowerState:     system.PowerState,
			Status:         system.Status.result(),
			Processors:     system.ProcessorSummary.Status.result(),
			ProcessorCount: system.ProcessorSummary.Count,
			Memory:         system.MemorySummary.Status.result(),
			MemoryGiB:      system.MemorySummary.TotalSystemMemoryGiB,
		})
		if system.Storage.ID != "" {
			storage = append(storage, system.ID+"|"+system.Storage.ID)
		}
		if system.LogServices.ID != "" {
			logServices = append(logServices, system.LogServices.ID)
		}
	}
	return systems, logServices, storage, nil
}

func collectRedfishChassis(ctx context.Context, client *redfishClient, path string) ([]*resultRedfishChassis, error) {
	result := []*resultRedfishChassis{}
	if path == "" {
		return result, nil
	}
	members, err := client.members(ctx, path)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		var chassis redfishChassisJSON
		if err := json.Unmarshal(member, &chassis); err != nil {
			client.warnings = append(client.warnings, fmt.Sprintf("chassis: %s", err))
			continue
		}
		if chassis.Status.State == "Absent" {
			continue
		}
		item := &resultRedfishChassis{
			ID:            chassis.ID,
			Name:          chassis.Name,
			ChassisType:   chassis.ChassisType,
			Manufacturer:  chassis.Manufacturer,
			Model:         chassis.Model,
			SerialNumber:  chassis.SerialNumber,
			Status:        chassis.Status.result(),
			Temperatures:  []*resultRedfishSensor{},
			Fans:          []*resultRedfishSensor{},
			PowerSupplies: []*resultRedfishPowerSupply{},
			Redundancy:    []*resultRedfishRedundancy{},
		}

		// The deprecated Thermal and Power resources contain everything in a single request,
		// the newer subsystems require a request per fan, sensor and power supply
		if chassis.Thermal.ID != "" {
			client.warn(collectRedfishThermal(ctx, client, chassis.Thermal.ID, item), "thermal of chassis "+chassis.ID)
		} else if chassis.ThermalSubsystem.ID != "" {
			client.warn(collectRedfishThermalSubsystem(ctx, client, &chassis, item), "thermal subsystem of chassis "+chassis.ID)
		}
		if chassis.Power.ID != "" {
			client.warn(collectRedfishPower(ctx, client, chassis.Power.ID, item), "power of chassis "+chassis.ID)
		} else if chassis.PowerSubsystem.ID != "" {
			client.warn(collectRedfishPowerSubsystem(ctx, client, &chassis, item), "power subsystem of chassis "+chassis.ID)
		}
		result = append(result, item)
	}
	return result, nil
}

func (c *redfishClient) warn(err error, context string) {
	if err != nil {
		c.warnings = append(c.warnings, fmt.Sprintf("%s: %s", context, err))
	}
}

func collectRedfishThermal(ctx context.Context, client *redfishClient, path string, chassis *resultRedfishChassis) error {
	var thermal redfishThermalJSON
	if err := client.getJSON(ctx, redfishPath(path), &thermal); err != nil {
		return err
	}
	for _, temperature := range thermal.Temperatures {
		if temperature.Status.State == "Absent" {
			continue
		}
		chassis.Temperatures = append(chassis.Temperatures, &resultRedfishSensor{
			Name:            temperature.Name,
			Reading:         temperature.ReadingCelsius,
			Units:           "Cel",
			PhysicalContext: temperature.PhysicalContext,
			UpperWarning:    temperature.UpperThresholdNonCritical,
			UpperCritical:   temperature.UpperThresholdCritical,
			LowerWarning:    temperature.LowerThresholdNonCritical,
			LowerCritical:   temperature.LowerThresholdCritical,
			Status:          temperature.Status.result(),
		})
	}
	for _, fan := range thermal.Fans {
		if fan.Status.State == "Absent" {
			continue
		}
		name := fan.Name
		if name == "" {
			name = fan.FanName
		}
		chassis.Fans = append(chassis.Fans, &resultRedfishSensor{
			Name:            name,
			Reading:         fan.Reading,
			Units:           fan.ReadingUnits,
			PhysicalContext: fan.PhysicalContext,
			UpperWarning:    fan.UpperThresholdNonCritical,
			UpperCritical:   fan.UpperThresholdCritical,
			LowerWarning:    fan.LowerThresholdNonCritical,
			LowerCritical:   fan.LowerThresholdCritical,
			Status:          fan.Status.result(),
		})
	}
	chassis.Redundancy = append(chassis.Redundancy, redfishRedundancy(thermal.Redundancy, "fans")...)
	return nil
}

func collectRedfishPower(ctx context.Context, client *redfishClient, path string, chassis *resultRedfishChassis) error {
	var power redfishPowerJSON
	if err := client.getJSON(ctx, redfishPath(path), &power); err != nil {
		return err
	}
	if len(power.PowerControl) > 0 {
		chassis.PowerConsumedWatts = power.PowerControl[0].PowerConsumedWatts
		chassis.PowerCapacityWatts = power.PowerControl[0].PowerCapacityWatts
	}
	for _, supply := range power.PowerSupplies {
		chassis.PowerSupplies = append(chassis.PowerSupplies, &resultRedfishPowerSupply{
			Name:            supply.Name,
			Model:           supply.Model,
			SerialNumber:    supply.SerialNumber,
			FirmwareVersion: supply.FirmwareVersion,
			CapacityWatts:   supply.PowerCapacityWatts,
			OutputWatts:     supply.LastPowerOutputWatts,
			Status:          supply.Status.result(),
		})
	}
	chassis.Redundancy = append(chassis.Redundancy, redfishRedundancy(power.Redundancy, "power_supplies")...)
	return nil
}

func redfishRedundancy(redundancy []redfishRedundancyJSON, group string) []*resultRedfishRedundancy {
	result := []*resultRedfishRedundancy{}
	for _, item := range redundancy {
		mode := item.Mode
		if mode == "" {
			mode = item.RedundancyType
		}
		result = append(result, &resultRedfishRedundancy{Name: item.Name, Group: group, Mode: mode, Status: item.Status.result()})
	}
	return result
}

func collectRedfishThermalSubsystem(ctx context.Context, client *redfishClient, chassisJSON *redfishChassisJSON, chassis *resultRedfishChassis) error {
	var subsystem struct {
		Fans           odataLink               `json:"Fans"`
		FanRedundancy  []redfishRedundancyJSON `json:"FanRedundancy"`
		ThermalMetrics odataLink               `json:"ThermalMetrics"`
	}
	if err := client.getJSON(ctx, chassisJSON.ThermalSubsystem.ID, &subsystem); err != nil {
		return err
	}
	chassis.Redundancy = append(chassis.Redundancy, redfishRedundancy(subsystem.FanRedundancy, "fans")...)

	if subsystem.Fans.ID != "" {
		fans, err := client.members(ctx, subsystem.Fans.ID)
		if err != nil {
			return err
		}
		for _, member := range fans {
			var fan struct {
				Name         string            `json:"Name"`
				Status       redfishStatusJSON `json:"Status"`
				SpeedPercent struct {
					Reading *float64 `json:"Reading"`
				} `json:"SpeedPercent"`
			}
			if json.Unmarshal(member, &fan) != nil || fan.Status.State == "Absent" {
				continue
			}
			chassis.Fans = append(chassis.Fans, &resultRedfishSensor{Name: fan.Name, Reading: fan.SpeedPercent.Reading, Units: "%", Status: fan.Status.result()})
		}
	}

	// The temperature sensors with thresholds are part of the sensors of the chassis
	if chassisJSON.Sensors.ID != "" {
		sensors, err := client.members(ctx, chassisJSON.Sensors.ID)
		if err != nil {
			return err
		}
		for _, member := range sensors {
			var sensor redfishSensorJSON
			if json.Unmarshal(member, &sensor) != nil || sensor.Status.State == "Absent" {
				continue
			}
			if sensor.ReadingType != "Temperature" && sensor.ReadingUnits != "Cel" {
				continue
			}
			chassis.Temperatures = append(chassis.Temperatures, &resultRedfishSensor{
				Name:            sensor.Name,
				Reading:         sensor.Reading,
				Units:           "Cel",
				PhysicalContext: sensor.PhysicalContext,
				UpperWarning:    sensor.Thresholds.UpperCaution.Reading,
				UpperCritical:   sensor.Thresholds.UpperCritical.Reading,
				LowerWarning:    sensor.Thresholds.LowerCaution.Reading,
				LowerCritical:   sensor.Thresholds.LowerCritical.Reading,
				Status:          sensor.Status.result(),
			})
		}
	} else if subsystem.ThermalMetrics.ID != "" {
		// Only the readings without thresholds and health
		var metrics struct {
			TemperatureReadingsCelsius []struct {
				DeviceName string   `json:"DeviceName"`
				Reading    *float64 `json:"Reading"`
			} `json:"TemperatureReadingsCelsius"`
		}
		if err := client.getJSON(ctx, subsystem.ThermalMetrics.ID, &metrics); err != nil {
			return err
		}
		for _, reading := range metrics.TemperatureReadingsCelsius {
			chassis.Temperatures = append(chassis.Temperatures, &resultRedfishSensor{Name: reading.DeviceName, Reading: reading.Reading, Units: "Cel", Status: &resultRedfishStatus{}})
		}
	}
	return nil
}

func collectRedfishPowerSubsystem(ctx context.Context, client *redfishClient, chassisJSON *redfishChassisJSON, chassis *resultRedfishChassis) error {
	var subsystem struct {
		CapacityWatts         *float64                `json:"CapacityWatts"`
		PowerSupplies         odataLink               `json:"PowerSupplies"`
		PowerSupplyRedundancy []redfishRedundancyJSON `json:"PowerSupplyRedundancy"`
	}
	if err := client.getJSON(ctx, chassisJSON.PowerSubsystem.ID, &subsystem); err != nil {
		return err
	}
	chassis.PowerCapacityWatts = subsystem.CapacityWatts
	chassis.Redundancy = append(chassis.Redundancy, redfishRedundancy(subsystem.PowerSupplyRedundancy, "power_supplies")...)

	if subsystem.PowerSupplies.ID != "" {
		supplies, err := client.members(ctx, subsystem.PowerSupplies.ID)
		if err != nil {
			return err
		}
		for _, member := range supplies {
			var supply struct {
				Name               string            `json:"Name"`
				Model              string            `json:"Model"`
				SerialNumber       string            `json:"SerialNumber"`
				FirmwareVersion    string            `json:"FirmwareVersion"`
				PowerCapacityWatts *float64          `json:"PowerCapacityWatts"`
				Status             redfishStatusJSON `json:"Status"`
			}
			if json.Unmarshal(member, &supply) != nil {
				continue
			}
			chassis.PowerSupplies = append(chassis.PowerSupplies, &resultRedfishPowerSupply{
				Name:            supply.Name,
				Model:           supply.Model,
				SerialNumber:    supply.SerialNumber,
				FirmwareVersion: supply.FirmwareVersion,
				CapacityWatts:   supply.PowerCapacityWatts,
				Status:          supply.Status.result(),
			})
		}
	}

	if chassisJSON.EnvironmentMetrics.ID != "" {
		var metrics struct {
			PowerWatts struct {
				Reading *float64 `json:"Reading"`
			} `json:"PowerWatts"`
		}
		if err := client.getJSON(ctx, chassisJSON.EnvironmentMetrics.ID, &metrics); err != nil {
			return err
		}
		chassis.PowerConsumedWatts = metrics.PowerWatts.Reading
	}
	return nil
}

// collectRedfishStorage reads the storage subsystems of all systems, links are "systemId|path"
func collectRedfishStorage(ctx context.Context, client *redfishClient, links []string) interface{} {
	result := []*resultRedfishStorage{}
	for _, link := range links {
		parts := strings.SplitN(link, "|", 2)
		members, err := client.members(ctx, parts[1])
		if err != nil {
			// e.g. the storage of a system which is powered off is not available on all BMCs
			client.warn(err, "storage of system "+parts[0])
			continue
		}
		for _, member := range members {
			var storage redfishStorageJSON
			if err := json.Unmarshal(member, &storage); err != nil {
				client.warn(err, "storage of system "+parts[0])
				continue
			}
			result = append(result, collectRedfishStorageDetails(ctx, client, parts[0], &storage))
		}
	}
	return result
}

func collectRedfishStorageDetails(ctx context.Context, client *redfishClient, system string, storage *redfishStorageJSON) *resultRedfishStorage {
	item := &resultRedfishStorage{
		ID:          storage.ID,
		Name:        storage.Name,
		System:      system,
		Status:      storage.Status.result(),
		Controllers: []*resultRedfishController{},
		Drives:      []*resultRedfishDrive{},
		Volumes:     []*resultRedfishVolume{},
	}

	for _, controller := range storage.StorageControllers {
		item.Controllers = append(item.Controllers, &resultRedfishController{
			Name: controller.Name, Model: controller.Model, FirmwareVersion: controller.FirmwareVersion, Status: controller.Status.result(),
		})
	}
	if len(storage.StorageControllers) == 0 && storage.Controllers.ID != "" {
		controllers, err := client.members(ctx, storage.Controllers.ID)
		client.warn(err, "controllers of storage "+storage.ID)
		for _, member := range controllers {
			var controller struct {
				Name            string            `json:"Name"`
				Model           string            `json:"Model"`
				FirmwareVersion string            `json:"FirmwareVersion"`
				Status          redfishStatusJSON `json:"Status"`
			}
			if json.Unmarshal(member, &controller) == nil {
				item.Controllers = append(item.Controllers, &resultRedfishController{
					Name: controller.Name, Model: controller.Model, FirmwareVersion: controller.FirmwareVersion, Status: controller.Status.result(),
				})
			}
		}
	}

	for _, link := range storage.Drives {
		data, err := client.resolve(ctx, link)
		if err != nil {
			client.warn(err, "drive of storage "+storage.ID)
			continue
		}
		var drive redfishDriveJSON
		if json.Unmarshal(data, &drive) != nil || drive.Status.State == "Absent" {
			continue
		}
		item.Drives = append(item.Drives, &resultRedfishDrive{
			ID:               drive.ID,
			Name:             drive.Name,
			Model:            strings.TrimSpace(drive.Model),
			SerialNumber:     strings.TrimSpace(drive.SerialNumber),
			MediaType:        drive.MediaType,
			Protocol:         drive.Protocol,
			CapacityBytes:    drive.CapacityBytes,
			FailurePredicted: drive.FailurePredicted,
			LifeLeftPercent:  drive.PredictedMediaLifeLeftPercent,
			Status:           drive.Status.result(),
		})
	}

	if storage.Volumes.ID != "" {
		volumes, err := client.members(ctx, storage.Volumes.ID)
		client.warn(err, "volumes of storage "+storage.ID)
		for _, member := range volumes {
			var volume redfishVolumeJSON
			if json.Unmarshal(member, &volume) != nil {
				continue
			}
			raidType := volume.RAIDType
			if raidType == "" {
				raidType = volume.VolumeType
			}
			item.Volumes = append(item.Volumes, &resultRedfishVolume{
				ID: volume.ID, Name: volume.Name, RAIDType: raidType, CapacityBytes: volume.CapacityBytes, Status: volume.Status.result(),
			})
		}
	}
	return item
}

func collectRedfishManagers(ctx context.Context, client *redfishClient, path string) ([]*resultRedfishManager, []string, error) {
	managers := []*resultRedfishManager{}
	var logServices []string
	if path == "" {
		return managers, nil, nil
	}
	members, err := client.members(ctx, path)
	if err != nil {
		return nil, nil, err
	}
	for _, member := range members {
		var manager redfishManagerJSON
		if err := json.Unmarshal(member, &manager); err != nil {
			continue
		}
		managers = append(managers, &resultRedfishManager{
			ID:              manager.ID,
			Name:            manager.Name,
			Model:           manager.Model,
			FirmwareVersion: manager.FirmwareVersion,
			Status:          manager.Status.result(),
		})
		if manager.LogServices.ID != "" {
			logServices = append(logServices, manager.LogServices.ID)
		}
	}
	return managers, logServices, nil
}

// collectRedfishEventlog reads the entries of the selected log services which are newer than the window
func collectRedfishEventlog(ctx context.Context, client *redfishClient, def *config.RedfishDefinition, collections []string, now time.Time) interface{} {
	result := &resultRedfishEventlog{
		Window:   def.EventlogWindow,
		Services: []string{},
		Entries:  []*resultRedfishLogEntry{},
	}
	since := now.Add(-time.Duration(def.EventlogWindow) * time.Second)

	var errors []string
	for _, collection := range collections {
		services, err := client.members(ctx, collection)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		for _, member := range services {
			var service redfishLogServiceJSON
			if json.Unmarshal(member, &service) != nil || service.Entries.ID == "" {
				continue
			}
			if !def.EventlogServicesRegexp.MatchString(service.ID) || (service.ServiceEnabled != nil && !*service.ServiceEnabled) {
				continue
			}
			result.Services = append(result.Services, service.ODataID)

			entries, err := client.members(ctx, service.Entries.ID)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
			for _, data := range entries {
				var entry redfishLogEntryJSON
				if json.Unmarshal(data, &entry) != nil {
					continue
				}
				if entry.Severity != "Warning" && entry.Severity != "Critical" {
					continue
				}
				created, err := time.Parse(time.RFC3339, entry.Created)
				if err != nil || created.Before(since) {
					continue
				}
				result.Entries = append(result.Entries, &resultRedfishLogEntry{
					Created:   created.Unix(),
					Severity:  entry.Severity,
					Message:   truncateString(strings.TrimSpace(entry.Message), redfishMaxMessageLength),
					MessageID: entry.MessageID,
					Service:   service.ODataID,
				})
			}
		}
	}

	// All log services failed, e.g. missing privileges
	if len(result.Services) == 0 && len(errors) > 0 {
		return map[string]string{"error": strings.Join(errors, "; ")}
	}
	for _, err := range errors {
		client.warnings = append(client.warnings, "eventlog: "+err)
	}

	sort.SliceStable(result.Entries, func(i, j int) bool {
		return result.Entries[i].Created > result.Entries[j].Created
	})
	if len(result.Entries) > redfishMaxEventlogEntries {
		result.Entries = result.Entries[:redfishMaxEventlogEntries]
	}
	return result
}

// truncateString shortens a string to a maximum number of runes
func truncateString(value string, length int) string {
	runes := []rune(value)
	if len(runes) <= length {
		return value
	}
	return string(runes[:length]) + "..."
}
