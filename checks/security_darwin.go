package checks

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func securityParts() []securityPart {
	return []securityPart{
		{"filevault", func(ctx context.Context) (interface{}, error) {
			output, err := runSecurityCommand(ctx, "/usr/bin/fdesetup", "status")
			if err != nil {
				return nil, err
			}
			return parseFileVaultStatus(output), nil
		}},
		{"sip", func(ctx context.Context) (interface{}, error) {
			output, err := runSecurityCommand(ctx, "/usr/bin/csrutil", "status")
			if err != nil {
				return nil, err
			}
			return parseSIPStatus(output), nil
		}},
		{"firewall", func(ctx context.Context) (interface{}, error) {
			const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
			globalState, err := runSecurityCommand(ctx, socketfilterfw, "--getglobalstate")
			if err != nil {
				return nil, err
			}
			stealthMode, err := runSecurityCommand(ctx, socketfilterfw, "--getstealthmode")
			if err != nil {
				return nil, err
			}
			return parseMacOSFirewall(globalState, stealthMode), nil
		}},
	}
}

func runSecurityCommand(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s failed: %s: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
