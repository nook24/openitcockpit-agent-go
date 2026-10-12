package checks

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCheckSecurityDarwin(t *testing.T) {
	r, err := (&CheckSecurity{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(js))

	result := r.(map[string]interface{})
	if res, ok := result["filevault"].(*resultFileVault); !ok || res.Status == "" {
		t.Errorf("unexpected filevault result: %+v", result["filevault"])
	}
	if res, ok := result["sip"].(*resultSIP); !ok || res.Status == "" {
		t.Errorf("unexpected sip result: %+v", result["sip"])
	}
	if _, ok := result["firewall"].(*resultMacOSFirewall); !ok {
		t.Errorf("unexpected firewall result: %+v", result["firewall"])
	}
}
