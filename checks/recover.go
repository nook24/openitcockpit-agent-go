package checks

import (
	"fmt"
	"runtime/debug"

	log "github.com/sirupsen/logrus"
)

// The check runner recovers panics of Check.Run, but not of the goroutines which are started by the checks
// (background collectors and parallel requests). A panic there would terminate the agent.

// protect runs fn and converts a panic into an error, e.g. a panic while parsing the data of a BMC
func protect[T any](name string, fn func() (T, error)) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = recoveredPanic(name, r)
		}
	}()
	return fn()
}

// panicError is a recovered panic
type panicError struct {
	message string
}

func (e *panicError) Error() string {
	return e.message
}

// recoveredPanic logs a recovered panic and returns it as error
func recoveredPanic(name string, r interface{}) error {
	log.Errorln(name, ": recovered from panic: ", r, "\n", string(debug.Stack()))
	return &panicError{message: fmt.Sprintf("%s: internal error: %v", name, r)}
}
