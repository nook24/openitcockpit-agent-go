package checks

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCheckNtpFreeBSD(t *testing.T) {
	sntpCacheMutex.Lock()
	sntpCache = nil
	sntpCacheMutex.Unlock()

	r, err := (&CheckNtp{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(r)
	t.Logf("result: %s", js)

	res := r.(*resultNtp)
	if res.Timestamp == 0 || res.TimestampMicro == 0 {
		t.Error("timestamps are missing")
	}
	// Either ntpd is synchronized (no NtpServer) or the offset was measured with SNTP or the query failed
	if res.SyncStatus && res.NtpServer == "" {
		t.Logf("offset of ntpd: %f", res.Offset)
	} else if res.SyncStatus {
		t.Logf("offset measured with SNTP against %s (%s)", res.NtpServer, res.NtpAddress)
	} else if res.QueryError == "" {
		t.Error("expected a query error if not synchronized")
	}
}
