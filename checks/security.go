package checks

import (
	"context"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// CheckSecurity gathers the state of security features of the operating system:
// Linux: SELinux and AppArmor
// Windows: Firewall and Microsoft Defender
// macOS: FileVault, System Integrity Protection and the application firewall
type CheckSecurity struct {
}

// Name will be used in the response as check name
func (c *CheckSecurity) Name() string {
	return "security"
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckSecurity) Run(ctx context.Context) (interface{}, error) {
	// Every part of the check can fail on its own. The error is reported as {"error": "..."} for the affected part only
	result := map[string]interface{}{}
	for _, part := range securityParts() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := part.run(ctx)
		if err != nil {
			result[part.name] = map[string]string{"error": err.Error()}
			continue
		}
		result[part.name] = res
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckSecurity) Configure(config *config.Configuration) (bool, error) {
	return config.Security, nil
}

type securityPart struct {
	name string
	run  func(ctx context.Context) (interface{}, error)
}
