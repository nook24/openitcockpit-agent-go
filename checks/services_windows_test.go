package checks

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

func TestGetServiceList(t *testing.T) {
	c := &CheckWinService{}
	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := r.([]*resultWindowsServices)

	if len(results) == 0 {
		t.Fatal("Empty result from WMI")
	}

	// Is Winmgmt running on al windows systems by default?
	needle := "Winmgmt"
	foundNeedle := false
	for _, result := range results {
		//js, _ := json.Marshal(result)
		//fmt.Println(string(js))

		if result.Name == needle {
			foundNeedle = true

			if result.Status != "Running" {
				t.Fatal("Winmgmt is not running")
			}

		}
	}

	if foundNeedle == false {
		t.Fatal("Needle not found: " + needle)
	}

}

// Services with a description in a missing file (e.g. ERROR_MUI_FILE_NOT_FOUND of the per-user services like
// CDPUserSvc_d59647d or ERROR_FILE_NOT_FOUND of WaaSMedicSvc) have an empty description
func TestServiceDescriptionMissingResource(t *testing.T) {
	scManager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseServiceHandle(scManager)

	c := &CheckWinService{}
	services, err := c.GetServiceListViaCAPI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		name, _ := windows.UTF16PtrFromString(service.Name)
		result := &resultWindowsServices{}
		err := fetchServiceConfiguration(scManager, name, result)
		if isMissingServiceDescription(errors.Cause(err)) {
			t.Errorf("%s: %s", service.Name, err)
		}
	}
}
