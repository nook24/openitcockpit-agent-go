package checks

import (
	"regexp"
	"strconv"
	"strings"
)

// The parsers for the macOS security commands are platform independent, so they can be tested on every platform

type resultFileVault struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"` // Output of "fdesetup status", e.g.: FileVault is On.
}

type resultSIP struct {
	Enabled bool   `json:"enabled"`
	Custom  bool   `json:"custom"` // Custom configuration, some protections may be disabled
	Status  string `json:"status"` // Output of "csrutil status"
}

type resultMacOSFirewall struct {
	Enabled     bool `json:"enabled"`
	BlockAll    bool `json:"block_all"`    // Block all incoming connections
	StealthMode bool `json:"stealth_mode"` // Do not respond to ping and connection attempts on closed ports
}

var macOSFirewallStateRegexp = regexp.MustCompile(`State = (\d+)`)

// parseFileVaultStatus parses the output of "fdesetup status"
// e.g.: "FileVault is On." or "FileVault is Off." or "FileVault is On.\nEncryption in progress: Percent completed = 45.1"
func parseFileVaultStatus(output string) *resultFileVault {
	output = strings.TrimSpace(output)
	return &resultFileVault{
		Enabled: strings.Contains(output, "FileVault is On"),
		Status:  output,
	}
}

// parseSIPStatus parses the output of "csrutil status"
// e.g.: "System Integrity Protection status: enabled." or "System Integrity Protection status: enabled (Custom Configuration)."
func parseSIPStatus(output string) *resultSIP {
	output = strings.TrimSpace(output)
	firstLine, _, _ := strings.Cut(output, "\n")
	firstLine = strings.ToLower(firstLine)
	return &resultSIP{
		Enabled: strings.Contains(firstLine, "status: enabled"),
		Custom:  strings.Contains(firstLine, "custom configuration"),
		Status:  output,
	}
}

// parseMacOSFirewall parses the output of "socketfilterfw --getglobalstate" and "--getstealthmode"
// e.g.: "Firewall is enabled. (State = 1)", "Firewall is blocking all non-essential incoming connections. (State = 2)"
// and "Firewall stealth mode is on" or "Stealth mode enabled" (older versions)
func parseMacOSFirewall(globalState, stealthMode string) *resultMacOSFirewall {
	res := &resultMacOSFirewall{}
	if match := macOSFirewallStateRegexp.FindStringSubmatch(globalState); match != nil {
		state, _ := strconv.Atoi(match[1])
		res.Enabled = state >= 1
		res.BlockAll = state == 2
	} else {
		res.Enabled = strings.Contains(strings.ToLower(globalState), "is enabled")
	}

	stealthMode = strings.ToLower(stealthMode)
	res.StealthMode = strings.Contains(stealthMode, "is on") || strings.Contains(stealthMode, "mode enabled")
	return res
}
