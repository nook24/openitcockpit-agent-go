package checks

import (
	"context"
	"testing"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

type closerTestCheck struct {
	name   string
	closed int
}

func (c *closerTestCheck) Name() string                                 { return c.name }
func (c *closerTestCheck) Run(ctx context.Context) (interface{}, error) { return nil, nil }
func (c *closerTestCheck) Configure(cfg *config.Configuration) (bool, error) {
	return true, nil
}
func (c *closerTestCheck) Close() { c.closed++ }

func TestCloseRemovedChecks(t *testing.T) {
	cpu := &closerTestCheck{name: "cpu"}
	redfish := &closerTestCheck{name: "redfish"}
	// The new configuration creates new instances of the enabled checks
	newCpu := &closerTestCheck{name: "cpu"}

	CloseRemovedChecks([]Check{cpu, redfish, &CheckMem{}}, []Check{newCpu})
	if cpu.closed != 0 || newCpu.closed != 0 {
		t.Error("an enabled check must not be closed")
	}
	if redfish.closed != 1 {
		t.Error("the disabled check was not closed")
	}

	// Checks without Closer are ignored
	CloseChecks([]Check{newCpu, &CheckMem{}})
	if newCpu.closed != 1 {
		t.Error("the check was not closed")
	}
	CloseRemovedChecks(nil, []Check{newCpu})
}
