package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const (
	postfixCommandTimeout = 20 * time.Second
	// Number of delay reasons in the result, ordered by the number of recipients
	postfixMaxDelayReasons = 10
	// Upper limit of distinct delay reasons which are counted, to limit the memory usage on huge queues
	postfixMaxDistinctReasons = 1000
	postfixMaxReasonLength    = 200
)

// Default locations of postqueue, which are often not part of the PATH of the agent service
var postqueueLocations = []string{
	"/usr/sbin/postqueue",
	"/usr/local/sbin/postqueue",
}

var postfixConfigFiles = []string{
	"/etc/postfix/main.cf",
	"/usr/local/etc/postfix/main.cf",
}

// All Postfix queues, see https://www.postfix.org/QSHAPE_README.html
var postfixQueueNames = []string{"maildrop", "incoming", "active", "deferred", "hold"}

// CheckPostfix gathers the size of the Postfix mail queues with "postqueue -j" (Postfix 3.1 or newer)
type CheckPostfix struct {
	postqueue string
}

// Name will be used in the response as check name
func (c *CheckPostfix) Name() string {
	return "postfix"
}

type resultPostfixQueue struct {
	Messages  int64 `json:"messages"`
	SizeBytes int64 `json:"size_bytes"`
	OldestAge int64 `json:"oldest_age"` // Age of the oldest message in seconds, 0 if the queue is empty
}

type resultPostfixDelayReason struct {
	Reason     string `json:"reason"` // e.g.: connect to mx.example.org[192.0.2.1]:25: Connection timed out
	Recipients int64  `json:"recipients"`
}

type resultPostfix struct {
	// false if the Postfix mail system is down. As root, postqueue then reads the queue directly.
	Running      bool                           `json:"running"`
	Messages     int64                          `json:"messages"` // All queues
	SizeBytes    int64                          `json:"size_bytes"`
	OldestAge    int64                          `json:"oldest_age"`
	Queues       map[string]*resultPostfixQueue `json:"queues"` // maildrop, incoming, active, deferred and hold
	DelayReasons []*resultPostfixDelayReason    `json:"delay_reasons"`
}

// One message of "postqueue -j"
type postqueueMessageJSON struct {
	QueueName   string `json:"queue_name"`
	ArrivalTime int64  `json:"arrival_time"`
	MessageSize int64  `json:"message_size"`
	Recipients  []struct {
		DelayReason string `json:"delay_reason"`
	} `json:"recipients"`
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckPostfix) Run(ctx context.Context) (interface{}, error) {
	if c.postqueue == "" {
		c.postqueue = findPostqueue()
	}
	if c.postqueue == "" {
		return nil, fmt.Errorf("postqueue: %w, please install Postfix 3.1 or newer", exec.ErrNotFound)
	}

	ctx, cancel := context.WithTimeout(ctx, postfixCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.postqueue, "-j")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("postqueue -j: %s", err)
	}

	// The queue can contain a lot of messages, so the output is parsed while it is read
	result, parseErr := parsePostqueue(stdout, time.Now())
	if parseErr != nil {
		// Read the rest of the output, so postqueue does not block
		_, _ = io.Copy(io.Discard, stdout)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("postqueue -j: timeout after %s", postfixCommandTimeout)
		}
		// e.g.: postqueue: fatal: Queue report unavailable - mail system is down
		return nil, fmt.Errorf("postqueue -j failed: %s: %s", err, strings.TrimSpace(stderr.String()))
	}
	if parseErr != nil {
		return nil, parseErr
	}
	// postqueue: warning: Mail system is down -- accessing queue directly (Connect to the Postfix showq service: Connection refused)
	result.Running = !strings.Contains(strings.ToLower(stderr.String()), "mail system is down")
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckPostfix) Configure(config *config.Configuration) (bool, error) {
	if !config.Postfix {
		return false, nil
	}
	// Only enable the check if Postfix is installed and configured
	c.postqueue = findPostqueue()
	if c.postqueue == "" {
		return false, nil
	}
	for _, path := range postfixConfigFiles {
		if _, err := os.Stat(path); err == nil {
			return true, nil
		}
	}
	return false, nil
}

func findPostqueue() string {
	if path, err := exec.LookPath("postqueue"); err == nil {
		return path
	}
	for _, path := range postqueueLocations {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// parsePostqueue parses the output of "postqueue -j", which contains one JSON object per message.
// An empty queue produces no output.
func parsePostqueue(r io.Reader, now time.Time) (*resultPostfix, error) {
	result := &resultPostfix{
		Queues:       map[string]*resultPostfixQueue{},
		DelayReasons: []*resultPostfixDelayReason{},
	}
	for _, name := range postfixQueueNames {
		result.Queues[name] = &resultPostfixQueue{}
	}
	reasons := map[string]int64{}

	decoder := json.NewDecoder(r)
	for {
		var message postqueueMessageJSON
		if err := decoder.Decode(&message); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("could not parse output of postqueue -j: %s", err)
		}

		queue, ok := result.Queues[message.QueueName]
		if !ok {
			queue = &resultPostfixQueue{}
			result.Queues[message.QueueName] = queue
		}
		age := int64(0)
		if message.ArrivalTime > 0 {
			age = now.Unix() - message.ArrivalTime
			if age < 0 {
				age = 0
			}
		}

		queue.Messages++
		queue.SizeBytes += message.MessageSize
		if age > queue.OldestAge {
			queue.OldestAge = age
		}
		result.Messages++
		result.SizeBytes += message.MessageSize
		if age > result.OldestAge {
			result.OldestAge = age
		}

		for _, recipient := range message.Recipients {
			reason := strings.TrimSpace(recipient.DelayReason)
			if reason == "" {
				continue
			}
			if len(reason) > postfixMaxReasonLength {
				reason = strings.ToValidUTF8(reason[:postfixMaxReasonLength], "") + "..."
			}
			if _, ok := reasons[reason]; ok || len(reasons) < postfixMaxDistinctReasons {
				reasons[reason]++
			}
		}
	}

	for reason, count := range reasons {
		result.DelayReasons = append(result.DelayReasons, &resultPostfixDelayReason{Reason: reason, Recipients: count})
	}
	sort.Slice(result.DelayReasons, func(i, j int) bool {
		if result.DelayReasons[i].Recipients != result.DelayReasons[j].Recipients {
			return result.DelayReasons[i].Recipients > result.DelayReasons[j].Recipients
		}
		return result.DelayReasons[i].Reason < result.DelayReasons[j].Reason
	})
	if len(result.DelayReasons) > postfixMaxDelayReasons {
		result.DelayReasons = result.DelayReasons[:postfixMaxDelayReasons]
	}
	return result, nil
}
