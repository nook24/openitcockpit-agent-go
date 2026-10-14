package checks

import (
	"strings"
	"testing"
	"time"
)

// postqueue -j output (one JSON object per message) in the format of the postqueue(1) manual page
const testPostqueue = `{"queue_name": "deferred", "queue_id": "4F2A11C0A12", "arrival_time": 1760000000, "message_size": 2145, "forced_expire": false, "sender": "root@example.org", "recipients": [{"address": "a@example.invalid", "delay_reason": "Host or domain name not found. Name service error for name=example.invalid type=MX: Host not found, try again"}, {"address": "b@example.invalid", "delay_reason": "Host or domain name not found. Name service error for name=example.invalid type=MX: Host not found, try again"}]}
{"queue_name": "deferred", "queue_id": "5B3C22D1B23", "arrival_time": 1760003000, "message_size": 1000, "forced_expire": false, "sender": "", "recipients": [{"address": "c@example.org", "delay_reason": "connect to mx.example.org[192.0.2.1]:25: Connection timed out"}]}
{"queue_name": "active", "queue_id": "6C4D33E2C34", "arrival_time": 1760003590, "message_size": 512, "forced_expire": false, "sender": "root@example.org", "recipients": [{"address": "d@example.org"}]}
{"queue_name": "hold", "queue_id": "7D5E44F3D45", "arrival_time": 1759996400, "message_size": 4096, "forced_expire": false, "sender": "root@example.org", "recipients": [{"address": "e@example.org"}]}
`

func TestParsePostqueue(t *testing.T) {
	result, err := parsePostqueue(strings.NewReader(testPostqueue), time.Unix(1760003600, 0))
	if err != nil {
		t.Fatal(err)
	}

	if result.Messages != 4 || result.SizeBytes != 7753 || result.OldestAge != 7200 {
		t.Errorf("unexpected totals: %+v", result)
	}
	if q := result.Queues["deferred"]; q.Messages != 2 || q.SizeBytes != 3145 || q.OldestAge != 3600 {
		t.Errorf("unexpected deferred queue: %+v", q)
	}
	if q := result.Queues["active"]; q.Messages != 1 || q.OldestAge != 10 {
		t.Errorf("unexpected active queue: %+v", q)
	}
	if q := result.Queues["hold"]; q.Messages != 1 || q.OldestAge != 7200 {
		t.Errorf("unexpected hold queue: %+v", q)
	}
	for _, name := range []string{"maildrop", "incoming"} {
		if q, ok := result.Queues[name]; !ok || q.Messages != 0 {
			t.Errorf("expected empty queue %s: %+v", name, q)
		}
	}

	if len(result.DelayReasons) != 2 {
		t.Fatalf("unexpected delay reasons: %+v", result.DelayReasons)
	}
	if r := result.DelayReasons[0]; r.Recipients != 2 || !strings.HasPrefix(r.Reason, "Host or domain name not found") {
		t.Errorf("the most common delay reason is expected first: %+v", r)
	}
}

func TestParsePostqueueEmptyAndInvalid(t *testing.T) {
	result, err := parsePostqueue(strings.NewReader(""), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.Messages != 0 || len(result.Queues) != 5 || result.DelayReasons == nil {
		t.Errorf("unexpected result for an empty queue: %+v", result)
	}

	if _, err := parsePostqueue(strings.NewReader("Mail queue is empty\n"), time.Now()); err == nil {
		t.Error("expected an error for output of postqueue -p")
	}
}

func TestParsePostqueueLimitsDelayReasons(t *testing.T) {
	var output strings.Builder
	for i := 0; i < postfixMaxDelayReasons+5; i++ {
		output.WriteString(`{"queue_name": "deferred", "arrival_time": 1, "message_size": 1, "recipients": [{"delay_reason": "reason ` + strings.Repeat("x", i) + `"}]}` + "\n")
	}
	output.WriteString(`{"queue_name": "deferred", "arrival_time": 1, "message_size": 1, "recipients": [{"delay_reason": "` + strings.Repeat("y", 500) + `"}]}` + "\n")

	result, err := parsePostqueue(strings.NewReader(output.String()), time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DelayReasons) != postfixMaxDelayReasons {
		t.Errorf("expected %d delay reasons, got %d", postfixMaxDelayReasons, len(result.DelayReasons))
	}
	for _, r := range result.DelayReasons {
		if len(r.Reason) > postfixMaxReasonLength+3 {
			t.Errorf("delay reason is not truncated: %d characters", len(r.Reason))
		}
	}
}
