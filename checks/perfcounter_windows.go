package checks

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
	"golang.org/x/sys/windows"
)

var (
	pdhDLL                          = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQuery                = pdhDLL.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounter        = pdhDLL.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData         = pdhDLL.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterArray = pdhDLL.NewProc("PdhGetFormattedCounterArrayW")
	procPdhCloseQuery               = pdhDLL.NewProc("PdhCloseQuery")
)

const (
	pdhFmtDouble   = 0x00000200
	pdhFmtNoCap100 = 0x00008000
	pdhMoreData    = 0x800007D2

	// PDH_FMT_COUNTERVALUE_ITEM_W has the same layout on 386, amd64 and arm64, as the union with the
	// double value is 8 byte aligned: szName (pointer) at 0, CStatus at 8, doubleValue at 16
	pdhItemSize          = 24
	pdhItemStatusOffset  = 8
	pdhItemValueOffset   = 16
	pdhStatusValidData   = 0x00000000
	pdhStatusNewData     = 0x00000001
	pdhFirstSampleWait   = 1 * time.Second
	pdhMaxInstanceValues = 1000
)

// Common PDH errors, see https://learn.microsoft.com/en-us/windows/win32/perfctrs/pdh-error-codes
var pdhErrors = map[uint32]string{
	0xC0000BB8: "object not found (PDH_CSTATUS_NO_OBJECT)",
	0xC0000BB9: "counter not found (PDH_CSTATUS_NO_COUNTER)",
	0xC0000BC0: "invalid counter path (PDH_CSTATUS_BAD_COUNTERNAME)",
	0xC0000BC6: "no valid data (PDH_INVALID_DATA)",
	0x800007D1: "instance not found (PDH_CSTATUS_NO_INSTANCE)",
	0x800007D5: "no data (PDH_NO_DATA)",
	0xC0000BBC: "access denied (PDH_ACCESS_DENIED)",
}

func pdhError(function string, status uintptr) error {
	code := uint32(status)
	if message, ok := pdhErrors[code]; ok {
		return fmt.Errorf("%s: %s", function, message)
	}
	return fmt.Errorf("%s failed with PDH error 0x%08X", function, code)
}

// The PDH queries are stored outside of CheckWindowsPerfCounter, because the checks get recreated on every reload.
// The queries stay open between check runs, as rate counters like "% Processor Time" require two samples.
var (
	pdhQueriesMutex sync.Mutex
	pdhQueries      = map[string]*pdhQuery{}
)

type pdhQuery struct {
	query   windows.Handle
	counter windows.Handle
	// Number of collected samples
	samples int
}

func (q *pdhQuery) close() {
	_, _, _ = procPdhCloseQuery.Call(uintptr(q.query))
}

// CheckWindowsPerfCounter reads Windows performance counters defined in the perfcounters.ini
type CheckWindowsPerfCounter struct {
	definitions []*config.PerfCounterDefinition
}

// Name will be used in the response as check name
func (c *CheckWindowsPerfCounter) Name() string {
	return "windows_perfcounters"
}

type resultPerfCounterValue struct {
	Instance string  `json:"instance"` // e.g.: _Total, 0 or empty for counters without instances
	Value    float64 `json:"value"`
}

type resultPerfCounter struct {
	Counter string                    `json:"counter"`
	Values  []*resultPerfCounterValue `json:"values"`
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckWindowsPerfCounter) Run(ctx context.Context) (interface{}, error) {
	pdhQueriesMutex.Lock()
	defer pdhQueriesMutex.Unlock()

	result := make(map[string]interface{}, len(c.definitions))
	var newQueries []*pdhQuery
	for _, definition := range c.definitions {
		if definition.ConfigError != "" {
			continue
		}
		query, ok := pdhQueries[definition.Counter]
		if !ok {
			var err error
			if query, err = openPdhQuery(definition.Counter); err != nil {
				result[definition.Name] = map[string]string{"error": err.Error()}
				continue
			}
			pdhQueries[definition.Counter] = query
		}
		if err := query.collect(); err != nil {
			result[definition.Name] = map[string]string{"error": err.Error()}
			continue
		}
		if query.samples == 1 {
			newQueries = append(newQueries, query)
		}
	}

	// Rate counters require a second sample
	if len(newQueries) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pdhFirstSampleWait):
		}
		for _, query := range newQueries {
			_ = query.collect()
		}
	}

	for _, definition := range c.definitions {
		if definition.ConfigError != "" {
			result[definition.Name] = map[string]string{"error": definition.ConfigError}
			continue
		}
		if _, ok := result[definition.Name]; ok {
			// Error while opening or collecting
			continue
		}
		values, err := pdhQueries[definition.Counter].values()
		if err != nil {
			result[definition.Name] = map[string]string{"error": err.Error()}
			continue
		}
		result[definition.Name] = &resultPerfCounter{
			Counter: definition.Counter,
			Values:  values,
		}
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckWindowsPerfCounter) Configure(cfg *config.Configuration) (bool, error) {
	c.definitions = cfg.PerfCounterConfiguration

	// Close the queries of removed counters
	pdhQueriesMutex.Lock()
	defer pdhQueriesMutex.Unlock()
	keep := make(map[string]bool, len(c.definitions))
	for _, definition := range c.definitions {
		keep[definition.Counter] = true
	}
	for counter, query := range pdhQueries {
		if !keep[counter] {
			query.close()
			delete(pdhQueries, counter)
		}
	}

	return len(c.definitions) > 0, nil
}

func openPdhQuery(counterPath string) (*pdhQuery, error) {
	if err := pdhDLL.Load(); err != nil {
		return nil, err
	}

	q := &pdhQuery{}
	if status, _, _ := procPdhOpenQuery.Call(0, 0, uintptr(unsafe.Pointer(&q.query))); status != 0 {
		return nil, pdhError("PdhOpenQuery", status)
	}

	path, err := windows.UTF16PtrFromString(counterPath)
	if err != nil {
		q.close()
		return nil, err
	}
	// The English counter path works independent of the language of Windows
	if status, _, _ := procPdhAddEnglishCounter.Call(uintptr(q.query), uintptr(unsafe.Pointer(path)), 0, uintptr(unsafe.Pointer(&q.counter))); status != 0 {
		q.close()
		return nil, pdhError(fmt.Sprintf("counter %s", counterPath), status)
	}
	return q, nil
}

func (q *pdhQuery) collect() error {
	if status, _, _ := procPdhCollectQueryData.Call(uintptr(q.query)); status != 0 {
		return pdhError("PdhCollectQueryData", status)
	}
	q.samples++
	return nil
}

func (q *pdhQuery) values() ([]*resultPerfCounterValue, error) {
	var bufferSize, itemCount uint32
	format := uintptr(pdhFmtDouble | pdhFmtNoCap100)

	status, _, _ := procPdhGetFormattedCounterArray.Call(uintptr(q.counter), format, uintptr(unsafe.Pointer(&bufferSize)), uintptr(unsafe.Pointer(&itemCount)), 0)
	if uint32(status) != pdhMoreData {
		return nil, pdhError("PdhGetFormattedCounterArray", status)
	}

	buffer := make([]byte, bufferSize)
	status, _, _ = procPdhGetFormattedCounterArray.Call(uintptr(q.counter), format, uintptr(unsafe.Pointer(&bufferSize)), uintptr(unsafe.Pointer(&itemCount)), uintptr(unsafe.Pointer(&buffer[0])))
	if status != 0 {
		return nil, pdhError("PdhGetFormattedCounterArray", status)
	}

	values := make([]*resultPerfCounterValue, 0, itemCount)
	for i := 0; i < int(itemCount) && i < pdhMaxInstanceValues; i++ {
		item := unsafe.Pointer(&buffer[i*pdhItemSize])
		cStatus := *(*uint32)(unsafe.Add(item, pdhItemStatusOffset))
		if cStatus != pdhStatusValidData && cStatus != pdhStatusNewData {
			continue
		}
		// The instance names are stored in the same buffer behind the items
		namePtr := *(**uint16)(item)
		values = append(values, &resultPerfCounterValue{
			Instance: windows.UTF16PtrToString(namePtr),
			Value:    *(*float64)(unsafe.Add(item, pdhItemValueOffset)),
		})
	}
	return values, nil
}
