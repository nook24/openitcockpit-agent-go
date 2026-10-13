package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestChecksCheckDocker(t *testing.T) {

	check := &CheckDocker{}

	cr, err := check.Run(context.Background())
	if err != nil {
		// Windows
		if strings.Contains(err.Error(), "error during connect") {
			fmt.Println("Docker not installed or running on this system ???")
			t.SkipNow()
		}
		// macOS and Linux
		if strings.Contains(err.Error(), "Is the docker daemon running") {
			fmt.Println("Docker not installed or running on this system ???")
			t.SkipNow()
		}
		if strings.Contains(err.Error(), "Got permission denied while trying to connect to the Docker daemon socket") {
			fmt.Println(err)
			t.SkipNow()
		}

		t.Fatal(err)

	}

	results, ok := cr.([]*resultDocker)
	if !ok {
		t.Fatal("False type")

	}

	if len(results) == 0 {
		fmt.Println("No running docker containers found")
	}

	if len(results) > 0 {
		for _, result := range results {
			if result.MemoryUsed == 0.0 {
				t.Fatal("Container memory usage is 0.0 - thats suspect!")
			}
		}
	}

}

func TestDockerRestartsLastHour(t *testing.T) {
	dockerRestartsMutex.Lock()
	dockerRestartSamples = map[string][]dockerRestartSample{}
	dockerRestartsMutex.Unlock()

	start := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	// Restarts before the agent started are not counted
	if restarts := dockerRestartsLastHour("abc", 5, start); restarts != 0 {
		t.Errorf("expected 0 restarts on the first sample, got %d", restarts)
	}
	if restarts := dockerRestartsLastHour("abc", 7, start.Add(30*time.Minute)); restarts != 2 {
		t.Errorf("expected 2 restarts, got %d", restarts)
	}
	if restarts := dockerRestartsLastHour("abc", 8, start.Add(50*time.Minute)); restarts != 3 {
		t.Errorf("expected 3 restarts, got %d", restarts)
	}
	// The first sample left the window, the sample of 10:30 is the new reference
	if restarts := dockerRestartsLastHour("abc", 8, start.Add(100*time.Minute)); restarts != 1 {
		t.Errorf("expected 1 restart within the last hour, got %d", restarts)
	}

	// Missing containers are kept for an hour (restart loops)
	forgetRemovedDockerContainers(map[string]bool{}, start.Add(110*time.Minute))
	dockerRestartsMutex.Lock()
	_, kept := dockerRestartSamples["abc"]
	dockerRestartsMutex.Unlock()
	if !kept {
		t.Error("samples of a missing container must be kept for an hour")
	}
	forgetRemovedDockerContainers(map[string]bool{}, start.Add(170*time.Minute))
	dockerRestartsMutex.Lock()
	_, kept = dockerRestartSamples["abc"]
	dockerRestartsMutex.Unlock()
	if kept {
		t.Error("samples of a removed container must be deleted after an hour")
	}
}
