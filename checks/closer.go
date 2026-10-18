package checks

// Closer is implemented by checks which start background goroutines (e.g. collectors of BMCs).
// The state of these goroutines is shared by all instances of a check, as the checks are created
// again with every reload of the configuration. Close stops the goroutines and releases their resources,
// e.g. the sessions on a BMC.
type Closer interface {
	Close()
}

// CloseChecks closes all checks, e.g. when the agent shuts down
func CloseChecks(checks []Check) {
	for _, check := range checks {
		if closer, ok := check.(Closer); ok {
			closer.Close()
		}
	}
}

// CloseRemovedChecks closes the checks of the previous configuration which are not part of the new configuration.
// Checks which are still enabled keep their background state, e.g. the samples of the CPU check.
func CloseRemovedChecks(previous, current []Check) {
	enabled := make(map[string]bool, len(current))
	for _, check := range current {
		enabled[check.Name()] = true
	}
	var removed []Check
	for _, check := range previous {
		if !enabled[check.Name()] {
			removed = append(removed, check)
		}
	}
	CloseChecks(removed)
}
