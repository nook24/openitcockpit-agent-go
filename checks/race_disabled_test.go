//go:build !race

package checks

// raceEnabled is true if the tests run with the race detector (go test -race)
const raceEnabled = false
