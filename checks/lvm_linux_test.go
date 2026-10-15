package checks

import (
	"context"
	"strings"
	"testing"
)

// Real output of LVM 2.03.31 (Proxmox VE 9) with an additional pool which is out of data space
const testLvsOutput = `  {
      "report": [
          {
              "lv": [
                  {"vg_name":"oitc-vg", "lv_name":"oitc-pool", "lv_attr":"twi-aotz--", "lv_size":"536870912", "data_percent":"3.33", "metadata_percent":"11.13", "lv_health_status":""},
                  {"vg_name":"pve", "lv_name":"data", "lv_attr":"twi-aotzD-", "lv_size":"107374182400", "data_percent":"100.00", "metadata_percent":"4.52", "lv_health_status":"out_of_data"},
                  {"vg_name":"vg2", "lv_name":"inactive", "lv_attr":"twi---tz--", "lv_size":"1073741824", "data_percent":"", "metadata_percent":"", "lv_health_status":""}
              ]
          }
      ]
      ,
      "log": [
      ]
  }
`

func TestParseLvs(t *testing.T) {
	result, err := parseLvs([]byte(testLvsOutput))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ThinPools) != 3 {
		t.Fatalf("expected 3 thin pools, got %d", len(result.ThinPools))
	}
	if p := result.ThinPools[0]; p.VG != "oitc-vg" || p.Name != "oitc-pool" || p.SizeBytes != 536870912 || p.DataPercent != 3.33 || p.MetadataPercent != 11.13 || !p.Active || p.Health != "" {
		t.Errorf("unexpected pool: %+v", p)
	}
	if p := result.ThinPools[1]; p.DataPercent != 100 || p.Health != "out_of_data" {
		t.Errorf("unexpected full pool: %+v", p)
	}
	if p := result.ThinPools[2]; p.Active || p.DataPercent != 0 {
		t.Errorf("unexpected inactive pool: %+v", p)
	}

	if _, err := parseLvs([]byte("  No volume groups found\n")); err == nil {
		t.Error("expected an error for invalid output")
	}
}

func TestCheckLvmWithFakeLvs(t *testing.T) {
	dir := t.TempDir()
	output := writeFixture(t, dir, "lvs.json", testLvsOutput)
	installFakeCommand(t, dir, "lvs", `case "$*" in *thin-pool*) cat `+output+` ;; *) exit 1 ;; esac`)

	r, err := (&CheckLvm{lvs: dir + "/lvs"}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.(*resultLvm).ThinPools) != 3 {
		t.Errorf("unexpected result: %+v", r)
	}

	installFakeCommand(t, dir, "lvs", `echo "  WARNING: Running as a non-root user. Functionality may be unavailable." >&2; exit 5`)
	if _, err := (&CheckLvm{lvs: dir + "/lvs"}).Run(context.Background()); err == nil || !strings.Contains(err.Error(), "non-root") {
		t.Errorf("expected the error of lvs, got: %v", err)
	}
}
