package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const firewallCommandTimeout = 10 * time.Second

// Commands to read the firewall rules, can be changed by tests
var (
	nftCommand          = "nft"
	iptablesSaveCommand = "iptables-save"
)

type resultLinuxFirewall struct {
	// true if a chain of the input hook drops packets by default or contains rules.
	// Only the input hook is evaluated, as Docker or libvirt create rules in other chains without filtering the host.
	Active      bool   `json:"active"`
	Backend     string `json:"backend"`      // nftables or iptables
	InputRules  int    `json:"input_rules"`  // Number of rules of the chains of the input hook
	InputPolicy string `json:"input_policy"` // accept or drop (drop if any chain of the input hook drops by default)
}

// Subset of "nft -j list ruleset"
type nftRulesetJSON struct {
	Nftables []struct {
		Chain *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Hook   string `json:"hook"`
			Policy string `json:"policy"`
		} `json:"chain"`
		Rule *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Chain  string `json:"chain"`
		} `json:"rule"`
	} `json:"nftables"`
}

// getLinuxFirewall evaluates the rules of nftables and iptables. Both are read, as iptables-legacy rules are not visible in nftables.
// The commands require root.
func getLinuxFirewall(ctx context.Context) (*resultLinuxFirewall, error) {
	var results []*resultLinuxFirewall
	var errs []string

	if path, err := exec.LookPath(nftCommand); err == nil {
		output, err := runFirewallCommand(ctx, path, "-j", "list", "ruleset")
		if err != nil {
			errs = append(errs, err.Error())
		} else if result, err := parseNftRuleset(output); err != nil {
			errs = append(errs, err.Error())
		} else {
			results = append(results, result)
		}
	}
	if path, err := exec.LookPath(iptablesSaveCommand); err == nil {
		output, err := runFirewallCommand(ctx, path)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			results = append(results, parseIptablesSave(output))
		}
	}

	if len(results) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
		}
		return nil, fmt.Errorf("neither nft nor iptables-save is installed")
	}

	// iptables-nft shows the same rules as nftables, so the backend with the most rules is reported instead of the sum
	best := results[0]
	for _, result := range results[1:] {
		if result.InputRules > best.InputRules || (result.InputPolicy == "drop" && best.InputPolicy != "drop") {
			best = result
		}
	}
	return best, nil
}

func runFirewallCommand(ctx context.Context, command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, firewallCommandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, command, args...).Output()
	if err != nil {
		var stderr string
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(exitError.Stderr))
		}
		return nil, fmt.Errorf("%s failed: %s: %s", command, err, stderr)
	}
	return output, nil
}

func parseNftRuleset(output []byte) (*resultLinuxFirewall, error) {
	var ruleset nftRulesetJSON
	if err := json.Unmarshal(output, &ruleset); err != nil {
		return nil, fmt.Errorf("could not parse the output of nft: %s", err)
	}

	result := &resultLinuxFirewall{Backend: "nftables", InputPolicy: "accept"}
	inputChains := map[string]bool{}
	for _, item := range ruleset.Nftables {
		if item.Chain != nil && item.Chain.Hook == "input" {
			// The family netdev or bridge does not filter the traffic to the host
			if item.Chain.Family != "ip" && item.Chain.Family != "ip6" && item.Chain.Family != "inet" {
				continue
			}
			inputChains[item.Chain.Family+"/"+item.Chain.Table+"/"+item.Chain.Name] = true
			if item.Chain.Policy == "drop" {
				result.InputPolicy = "drop"
			}
		}
	}
	for _, item := range ruleset.Nftables {
		if item.Rule != nil && inputChains[item.Rule.Family+"/"+item.Rule.Table+"/"+item.Rule.Chain] {
			result.InputRules++
		}
	}
	result.Active = result.InputRules > 0 || result.InputPolicy == "drop"
	return result, nil
}

// parseIptablesSave evaluates the INPUT chain of the filter table of "iptables-save"
func parseIptablesSave(output []byte) *resultLinuxFirewall {
	result := &resultLinuxFirewall{Backend: "iptables", InputPolicy: "accept"}
	table := ""
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "*"):
			table = line[1:]
		case table != "filter":
			continue
		case strings.HasPrefix(line, ":INPUT "):
			if fields := strings.Fields(line); len(fields) > 1 && fields[1] == "DROP" {
				result.InputPolicy = "drop"
			}
		case strings.HasPrefix(line, "-A INPUT "):
			result.InputRules++
		}
	}
	result.Active = result.InputRules > 0 || result.InputPolicy == "drop"
	return result
}
