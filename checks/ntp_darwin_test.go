package checks

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCheckNtpDarwin(t *testing.T) {
	sntpCacheMutex.Lock()
	sntpCache = nil
	sntpCacheMutex.Unlock()

	c := &CheckNtp{}
	for run := 1; run <= 2; run++ {
		r, err := c.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		js, _ := json.Marshal(r)
		t.Logf("run %d: %s", run, js)

		res := r.(*resultNtp)
		if res.Timestamp == 0 || res.TimestampMicro == 0 {
			t.Error("timestamps are missing")
		}
		if res.QueryError != "" {
			// e.g. no internet connection, the openITCOCKPIT server compares the timestamps instead
			t.Skip("time server not reachable: ", res.QueryError)
		}
		if !res.SyncStatus || res.NtpServer == "" || res.Stratum == 0 || res.MeasuredAt == 0 {
			t.Errorf("unexpected result: %+v", res)
		}
	}
}
