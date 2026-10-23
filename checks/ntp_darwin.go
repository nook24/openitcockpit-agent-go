package checks

import (
	"context"
)

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckNtp) Run(ctx context.Context) (interface{}, error) {
	// macOS does not support timex like Linux and querying timed requires admin privileges.
	// So the agent measures the offset to the configured time server with an SNTP query.
	// macOS writes the time server of the system settings ("Set time and date automatically") to /etc/ntp.conf
	servers := ntpServersFromConfig([]string{"/etc/ntp.conf"}, "time.apple.com")
	return runSNTPCheck(ctx, servers), nil
}
