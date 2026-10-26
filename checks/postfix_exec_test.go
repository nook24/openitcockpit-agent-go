//go:build linux
// +build linux

package checks

import (
	"context"
	"strings"
	"testing"
)

func TestCheckPostfixWithFakePostqueue(t *testing.T) {
	dir := t.TempDir()
	queue := writeFixture(t, dir, "queue.json", testPostqueue)
	installFakeCommand(t, dir, "postqueue", `[ "$1" = "-j" ] && cat `+queue)

	r, err := (&CheckPostfix{postqueue: dir + "/postqueue"}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result := r.(*resultPostfix); !result.Running || result.Messages != 4 || result.Queues["deferred"].Messages != 2 {
		t.Errorf("unexpected result: %+v", result)
	}

	// Postfix is not running, but root can read the queue directly
	installFakeCommand(t, dir, "postqueue", `echo "postqueue: warning: Mail system is down -- accessing queue directly (Connect to the Postfix showq service: Connection refused)" >&2; cat `+queue)
	r, err = (&CheckPostfix{postqueue: dir + "/postqueue"}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result := r.(*resultPostfix); result.Running || result.Messages != 4 {
		t.Errorf("expected a stopped mail system with messages: %+v", result)
	}

	// Postfix is not running and the queue can not be read (not root)
	installFakeCommand(t, dir, "postqueue", `echo "postqueue: fatal: Queue report unavailable - mail system is down" >&2; exit 69`)
	_, err = (&CheckPostfix{postqueue: dir + "/postqueue"}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mail system is down") {
		t.Errorf("expected the error of postqueue, got: %v", err)
	}

	// Invalid output, e.g. Postfix < 3.1 without -j
	installFakeCommand(t, dir, "postqueue", `echo "postqueue: invalid option -- 'j'"; exit 64`)
	_, err = (&CheckPostfix{postqueue: dir + "/postqueue"}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "postqueue -j failed") {
		t.Errorf("expected an error for an old Postfix version, got: %v", err)
	}
}
