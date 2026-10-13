package checks

import (
	"context"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/utils"
	log "github.com/sirupsen/logrus"
)

// Configuration files of the NTP implementations available on FreeBSD
var freebsdNtpConfigFiles = []string{
	"/etc/ntp.conf",              // ntpd of the base system
	"/usr/local/etc/chrony.conf", // net/chrony
	"/usr/local/etc/ntpd.conf",   // net/openntpd
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckNtp) Run(ctx context.Context) (interface{}, error) {
	// If ntpd is running and synchronized, its offset is used
	if result, ok := ntpdOffset(ctx); ok {
		return result, nil
	}

	// Otherwise the agent measures the offset to the configured time server with an SNTP query.
	// This also works if no NTP service is running or ntpd is not synchronized yet.
	servers := ntpServersFromConfig(freebsdNtpConfigFiles, "0.freebsd.pool.ntp.org")
	return runSNTPCheck(ctx, servers), nil
}

// ntpdOffset returns the offset of ntpd, if ntpd is running and synchronized
func ntpdOffset(ctx context.Context) (*resultNtp, bool) {
	//ntpq -c rv
	//associd=0 status=c016 leap_alarm, sync_unspec, 1 event, restart,
	//version="ntpd 4.2.8p18-a (1)", processor="amd64",
	//system="FreeBSD/15.0-RELEASE", leap=11, stratum=16, precision=-25,
	//rootdelay=0.000, rootdisp=0.015, refid=INIT, reftime=(no time),
	//clock=ecdb11d2.88100972  Wed, Dec  3 2025 20:45:22.531, peer=0, tc=3,
	//mintc=3, offset=+0.000000, frequency=+0.000, sys_jitter=0.000000,
	//clk_jitter=0.000, clk_wander=0.000, leapsec=201701010000,
	//expire=202606280000
	//
	// On some systems ntpq and the ntp service were crashing, in this case the SNTP query is used

	timeout := 10 * time.Second
	command := "ntpq -c rv"

	result, err := utils.RunCommand(ctx, utils.CommandArgs{
		Command: command,
		Timeout: timeout,
	})
	if err != nil || result.RC > 0 {
		log.Debugf("Error while executing '%v': %v\n", command, err)
		return nil, false
	}

	syncStatus, offset := parseNtpqOutput(result.Stdout)
	if !syncStatus {
		return nil, false
	}

	return &resultNtp{
		Timestamp:      time.Now().Unix(),
		TimestampMicro: time.Now().UnixMicro(),
		SyncStatus:     true,
		Offset:         offset,
	}, true
}
