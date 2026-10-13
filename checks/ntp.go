package checks

import (
	"fmt"
	"strings"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// CheckNtp gathers information about  time offset between the system clock and the chosen time source (NTP)
type CheckNtp struct {
}

// Name will be used in the response as check name
func (c *CheckNtp) Name() string {
	return "ntp"
}

type resultNtp struct {
	//Meta data
	Timestamp      int64 // Timestamp of the last check evaluation
	TimestampMicro int64 // Timestamp of the last check evaluation in micro seconds (can be used if no NTP server is configured or on macOS)

	SyncStatus bool    // Is synchronized with an NTP server
	Offset     float64 // Time offset between local system and NTP server in seconds

	// Only set if the offset was measured by the agent with an SNTP query (macOS)
	NtpServer      string  `json:",omitempty"` // e.g.: time.euro.apple.com
	NtpAddress     string  `json:",omitempty"` // IP address of the NTP server
	Stratum        uint8   `json:",omitempty"`
	RoundTripDelay float64 `json:",omitempty"` // Seconds
	MeasuredAt     int64   `json:",omitempty"` // Unix timestamp of the SNTP query, the result is cached for 5 minutes
	QueryError     string  `json:",omitempty"` // Error of the SNTP query. The openITCOCKPIT server compares the timestamps instead
}

// Configure the command or return false if the command was disabled
func (c *CheckNtp) Configure(config *config.Configuration) (bool, error) {
	return config.Ntp, nil
}

// parseNtpqOutput returns if ntpd is synchronized and the offset in seconds.
// ntpd is synchronized if it selected a time source (sync_ntp, sync_pps, ...) and the leap indicator is not
// "alarm" (11). Right after the start ntpd reports "leap_alarm, sync_ntp" and an offset of 0 until the clock is set.
func parseNtpqOutput(output string) (bool, float64) {
	hasSource := false
	leapAlarm := false
	offset := 0.0

	for _, line := range strings.Split(output, ",") {
		line = strings.TrimSpace(line)
		for _, field := range strings.Fields(line) {
			switch {
			case field == "leap_alarm":
				leapAlarm = true
			case strings.HasPrefix(field, "sync_") && field != "sync_unspec":
				hasSource = true
			}
		}
		if line == "leap=11" {
			leapAlarm = true
		}
		if strings.HasPrefix(line, "offset=") {
			var val float64
			_, err := fmt.Sscanf(line, "offset=%f", &val)
			if err == nil {
				offset = val / 1000.0 // ntpq offset is in ms, convert to seconds
			}
		}
	}
	return hasSource && !leapAlarm, offset
}
