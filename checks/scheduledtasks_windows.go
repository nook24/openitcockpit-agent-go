package checks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// TASK_STATE of the Task Scheduler API
var windowsTaskStates = map[int32]string{
	0: "unknown",
	1: "disabled",
	2: "queued",
	3: "ready",
	4: "running",
}

// CheckWindowsScheduledTasks gathers the state and last result of the Windows scheduled tasks
type CheckWindowsScheduledTasks struct {
	includeMicrosoft bool
}

// Name will be used in the response as check name
func (c *CheckWindowsScheduledTasks) Name() string {
	return "windows_scheduled_tasks"
}

type resultWindowsScheduledTask struct {
	Path           string `json:"path"`  // e.g.: \Backup\Nightly database backup
	Name           string `json:"name"`  // e.g.: Nightly database backup
	State          string `json:"state"` // unknown, disabled, queued, ready or running
	Enabled        bool   `json:"enabled"`
	LastRunTime    int64  `json:"last_run_time"`    // Unix timestamp, 0 if the task did not run yet
	LastTaskResult int64  `json:"last_task_result"` // 0 = success, see https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-error-and-success-constants
	NextRunTime    int64  `json:"next_run_time"`    // Unix timestamp, 0 if the task has no trigger
	MissedRuns     int64  `json:"missed_runs"`
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckWindowsScheduledTasks) Run(ctx context.Context) (interface{}, error) {
	// COM has to be initialized for the current OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oleError *ole.OleError
		// S_FALSE = COM is already initialized for this thread
		if !errors.As(err, &oleError) || oleError.Code() != 1 {
			return nil, err
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return nil, fmt.Errorf("could not create Schedule.Service: %s", err)
	}
	defer unknown.Release()
	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	defer service.Release()

	if _, err := oleutil.CallMethod(service, "Connect"); err != nil {
		return nil, fmt.Errorf("could not connect to the task scheduler: %s", err)
	}

	rootVariant, err := oleutil.CallMethod(service, "GetFolder", `\`)
	if err != nil {
		return nil, err
	}
	root := rootVariant.ToIDispatch()
	defer root.Release()

	tasks := []*resultWindowsScheduledTask{}
	if err := c.readTaskFolder(ctx, root, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckWindowsScheduledTasks) Configure(cfg *config.Configuration) (bool, error) {
	c.includeMicrosoft = cfg.WindowsTasksIncludeMicrosoft
	return cfg.WindowsTasks, nil
}

func (c *CheckWindowsScheduledTasks) readTaskFolder(ctx context.Context, folder *ole.IDispatch, tasks *[]*resultWindowsScheduledTask) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	path := taskStringProperty(folder, "Path")
	// The \Microsoft\ folder contains hundreds of tasks of Windows itself
	if !c.includeMicrosoft && (strings.EqualFold(path, `\Microsoft`) || strings.HasPrefix(strings.ToLower(path), `\microsoft\`)) {
		return nil
	}

	// TASK_ENUM_HIDDEN = 1
	tasksVariant, err := oleutil.CallMethod(folder, "GetTasks", 1)
	if err != nil {
		// e.g. access denied for a folder
		return nil
	}
	taskCollection := tasksVariant.ToIDispatch()
	defer taskCollection.Release()

	err = oleutil.ForEach(taskCollection, func(v *ole.VARIANT) error {
		task := v.ToIDispatch()
		defer task.Release()
		*tasks = append(*tasks, readScheduledTask(task))
		return nil
	})
	if err != nil {
		return err
	}

	foldersVariant, err := oleutil.CallMethod(folder, "GetFolders", 0)
	if err != nil {
		return nil
	}
	folders := foldersVariant.ToIDispatch()
	defer folders.Release()

	return oleutil.ForEach(folders, func(v *ole.VARIANT) error {
		subFolder := v.ToIDispatch()
		defer subFolder.Release()
		return c.readTaskFolder(ctx, subFolder, tasks)
	})
}

func readScheduledTask(task *ole.IDispatch) *resultWindowsScheduledTask {
	res := &resultWindowsScheduledTask{
		Path:  taskStringProperty(task, "Path"),
		Name:  taskStringProperty(task, "Name"),
		State: "unknown",
	}
	if v, err := oleutil.GetProperty(task, "State"); err == nil {
		if state, ok := windowsTaskStates[int32(variantInt(v))]; ok {
			res.State = state
		}
		_ = v.Clear()
	}
	if v, err := oleutil.GetProperty(task, "Enabled"); err == nil {
		res.Enabled, _ = v.Value().(bool)
		_ = v.Clear()
	}
	if v, err := oleutil.GetProperty(task, "LastTaskResult"); err == nil {
		// HRESULTs like 0x8007010B are negative as int32, but are documented and searched as unsigned value
		res.LastTaskResult = int64(uint32(variantInt(v)))
		_ = v.Clear()
	}
	if v, err := oleutil.GetProperty(task, "NumberOfMissedRuns"); err == nil {
		res.MissedRuns = variantInt(v)
		_ = v.Clear()
	}
	res.LastRunTime = taskTimeProperty(task, "LastRunTime")
	res.NextRunTime = taskTimeProperty(task, "NextRunTime")
	return res
}

// taskStringProperty returns a string property. The BSTR of the VARIANT has to be freed with Clear.
func taskStringProperty(object *ole.IDispatch, name string) string {
	v, err := oleutil.GetProperty(object, name)
	if err != nil {
		return ""
	}
	defer v.Clear()
	return v.ToString()
}

// taskTimeProperty returns a Unix timestamp or 0 if the time is not set
func taskTimeProperty(task *ole.IDispatch, name string) int64 {
	v, err := oleutil.GetProperty(task, name)
	if err != nil {
		return 0
	}
	defer v.Clear()
	if v.VT != ole.VT_DATE {
		return 0
	}
	t := variantDateToTime(math.Float64frombits(uint64(v.Val)), time.Local)
	// Tasks which did not run yet return 1999-11-30 or 1899-12-30
	if t.Year() < 2000 {
		return 0
	}
	return t.Unix()
}

// variantDateToTime converts an OLE Automation date (VT_DATE) of the given location. The date is the number of days since
// 1899-12-30, the fraction is the time of the day (also for negative dates).
//
// VARIANT.Value() of go-ole is not used, it converts the date with VariantTimeToSystemTime, which crashes the agent on
// Windows ARM64: go-ole passes the double in two integer registers, but the function expects it in a floating point
// register and writes the result to an invalid address.
func variantDateToTime(date float64, location *time.Location) time.Time {
	days, fraction := math.Modf(date)
	seconds := int(math.Round(math.Abs(fraction) * 86400))
	return time.Date(1899, 12, 30+int(days), 0, 0, seconds, 0, location)
}

func variantInt(v *ole.VARIANT) int64 {
	switch value := v.Value().(type) {
	case int32:
		return int64(value)
	case int64:
		return value
	case uint32:
		return int64(value)
	case int16:
		return int64(value)
	case int:
		return int64(value)
	}
	return 0
}
