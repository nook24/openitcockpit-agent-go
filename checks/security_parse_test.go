package checks

import "testing"

func TestParseFileVaultStatus(t *testing.T) {
	for output, expected := range map[string]bool{
		"FileVault is On.\n":  true,
		"FileVault is Off.\n": false,
		"FileVault is On.\nEncryption in progress: Percent completed = 45.1\n":  true,
		"FileVault is Off.\nDecryption in progress: Percent completed = 12.0\n": false,
	} {
		if res := parseFileVaultStatus(output); res.Enabled != expected || res.Status == "" {
			t.Errorf("%q: expected enabled=%v: %+v", output, expected, res)
		}
	}
}

func TestParseSIPStatus(t *testing.T) {
	res := parseSIPStatus("System Integrity Protection status: enabled.\n")
	if !res.Enabled || res.Custom {
		t.Errorf("unexpected result: %+v", res)
	}
	res = parseSIPStatus("System Integrity Protection status: disabled.\n")
	if res.Enabled {
		t.Errorf("unexpected result: %+v", res)
	}
	res = parseSIPStatus("System Integrity Protection status: enabled (Custom Configuration).\n\nConfiguration:\n\tApple Internal: disabled\n\tKext Signing: disabled\n")
	if !res.Enabled || !res.Custom {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestParseMacOSFirewall(t *testing.T) {
	for _, test := range []struct {
		global, stealth                string
		enabled, blockAll, stealthMode bool
	}{
		{"Firewall is disabled. (State = 0)\n", "Firewall stealth mode is off\n", false, false, false},
		{"Firewall is enabled. (State = 1)\n", "Firewall stealth mode is on\n", true, false, true},
		{"Firewall is blocking all non-essential incoming connections. (State = 2)\n", "Stealth mode enabled\n", true, true, true},
		{"Firewall is enabled.\n", "Stealth mode disabled\n", true, false, false},
	} {
		res := parseMacOSFirewall(test.global, test.stealth)
		if res.Enabled != test.enabled || res.BlockAll != test.blockAll || res.StealthMode != test.stealthMode {
			t.Errorf("%q %q: unexpected result: %+v", test.global, test.stealth, res)
		}
	}
}
