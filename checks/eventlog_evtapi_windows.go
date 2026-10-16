package checks

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// This version of the event log check uses the Windows Event Log API (wevtapi.dll) directly, like the Event Viewer does.
// It does not depend on WMI or PowerShell, which caused memory leaks and blue screens in the past.
//
// Only new records get queried: The first run queries the records of the configured time window (wineventlog-age),
// every following run only queries records with a higher EventRecordID. The records are kept in memory until
// they are older than the time window, so the result is the same as with the WMI and PowerShell methods.

var (
	wevtapiDLL                   = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery                 = wevtapiDLL.NewProc("EvtQuery")
	procEvtNext                  = wevtapiDLL.NewProc("EvtNext")
	procEvtClose                 = wevtapiDLL.NewProc("EvtClose")
	procEvtCreateRenderContext   = wevtapiDLL.NewProc("EvtCreateRenderContext")
	procEvtRender                = wevtapiDLL.NewProc("EvtRender")
	procEvtOpenPublisherMetadata = wevtapiDLL.NewProc("EvtOpenPublisherMetadata")
	procEvtFormatMessage         = wevtapiDLL.NewProc("EvtFormatMessage")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200

	evtRenderContextSystem = 1
	evtRenderEventValues   = 0
	evtRenderEventXML      = 1

	evtFormatMessageEvent = 1
	evtFormatMessageTask  = 3

	// EVT_SYSTEM_PROPERTY_ID
	evtSystemProviderName  = 0
	evtSystemEventID       = 2
	evtSystemLevel         = 4
	evtSystemTask          = 5
	evtSystemKeywords      = 7
	evtSystemTimeCreated   = 8
	evtSystemEventRecordID = 9
	evtSystemComputer      = 15

	// EVT_VARIANT has the same layout on 386, amd64 and arm64: 8 byte value, 4 byte count, 4 byte type
	evtVariantSize       = 16
	evtVariantTypeOffset = 12
	evtVarTypeNull       = 0

	// Audit keywords of the Security event log
	evtKeywordAuditFailure = 0x10000000000000
	evtKeywordAuditSuccess = 0x20000000000000

	// .NET EventLogEntryType, as used by the PowerShell method and the check receiver
	entryTypeError        = 1
	entryTypeWarning      = 2
	entryTypeInformation  = 4
	entryTypeAuditSuccess = 8
	entryTypeAuditFailure = 16

	evtNextBatchSize       = 100
	evtNextTimeoutMs       = 5000
	evtMaxMessageLength    = 4096
	evtDefaultMaxRecords   = 1000
	errorNoMoreItems       = syscall.Errno(259)
	errorInsufficientBuffr = syscall.Errno(122)
)

// The state is stored outside of CheckWindowsEventLog, because the checks get recreated on every reload of the agent
var (
	evtStatesMutex sync.Mutex
	evtStates      = map[string]*evtChannelState{}
	// Publisher metadata is required to format the messages. 0 = publisher has no metadata
	evtPublishers = map[string]windows.Handle{}
)

type evtChannelState struct {
	initialized  bool
	lastRecordID uint64
	// Records of the time window, sorted by EventRecordID.
	// The time of a record can be older than the time of the previous record
	records []*resultEvent
}

// evtRenderBuffer is reused for all records of a check run. []uint64 guarantees the alignment of EVT_VARIANT
type evtRenderBuffer struct {
	data []uint64
}

func (b *evtRenderBuffer) bytes(size uint32) []byte {
	if needed := int(size+7) / 8; len(b.data) < needed {
		b.data = make([]uint64, needed)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&b.data[0])), len(b.data)*8)
}

// RunEvtApi queries the event logs with the Windows Event Log API
func (c *CheckWindowsEventLog) RunEvtApi(ctx context.Context) (interface{}, error) {
	if err := wevtapiDLL.Load(); err != nil {
		return nil, err
	}

	evtStatesMutex.Lock()
	defer evtStatesMutex.Unlock()

	renderContext, _, err := procEvtCreateRenderContext.Call(0, 0, evtRenderContextSystem)
	if renderContext == 0 {
		return nil, fmt.Errorf("EvtCreateRenderContext: %s", err)
	}
	defer evtClose(windows.Handle(renderContext))

	maxRecords := c.maxRecords
	if maxRecords <= 0 {
		maxRecords = evtDefaultMaxRecords
	}

	result := make(map[string][]*resultEvent, len(c.logfiles))
	buffer := &evtRenderBuffer{}
	for _, channel := range c.logfiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		state, ok := evtStates[channel]
		if !ok {
			state = &evtChannelState{}
			evtStates[channel] = state
		}

		if err := c.updateEvtChannel(ctx, channel, state, windows.Handle(renderContext), buffer, maxRecords); err != nil {
			// The channel is missing in the result, so the check receiver reports "Log type not found"
			log.Errorln("Event Log: ", channel, ": ", err)
			continue
		}

		records := make([]*resultEvent, len(state.records))
		copy(records, state.records)
		result[channel] = records
	}
	return result, nil
}

func (c *CheckWindowsEventLog) updateEvtChannel(ctx context.Context, channel string, state *evtChannelState, renderContext windows.Handle, buffer *evtRenderBuffer, maxRecords int64) error {
	latestRecordID, err := evtLatestRecordID(channel, renderContext, buffer)
	if err != nil {
		return err
	}

	if state.initialized && latestRecordID < state.lastRecordID {
		// The event log got cleared, the record ids start at 1 again
		log.Infoln("Event Log: ", channel, " got cleared")
		*state = evtChannelState{}
	}

	var query string
	switch {
	case !state.initialized:
		// First run: all records of the time window
		query = fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", c.age.Milliseconds())
	case latestRecordID > state.lastRecordID:
		// Only new records
		query = fmt.Sprintf("*[System[EventRecordID > %d]]", state.lastRecordID)
	}

	// Records which got written after evtLatestRecordID are returned by the query as well,
	// so the highest record id which was actually read is the start of the next query
	lastRecordID := latestRecordID
	if query != "" {
		// The records are read newest first, so the newest records are kept if there are more than maxRecords
		newRecords, err := evtReadRecords(ctx, channel, query, renderContext, buffer, maxRecords)
		if err != nil {
			return err
		}
		if len(newRecords) >= int(maxRecords) {
			log.Warningln("Event Log: ", channel, ": more than ", maxRecords, " new records, older records are skipped (wineventlog-max-records)")
		}
		for i := len(newRecords) - 1; i >= 0; i-- {
			state.records = append(state.records, newRecords[i])
			if newRecords[i].Index > 0 && uint64(newRecords[i].Index) > lastRecordID {
				lastRecordID = uint64(newRecords[i].Index)
			}
		}
	}
	state.initialized = true
	if lastRecordID > state.lastRecordID {
		state.lastRecordID = lastRecordID
	}

	// Discard records which are older than the time window
	windowStart := time.Now().Add(-c.age).Unix()
	records := make([]*resultEvent, 0, len(state.records))
	for _, record := range state.records {
		if record.TimeGenerated >= windowStart {
			records = append(records, record)
		}
	}
	if len(records) > int(maxRecords) {
		records = records[len(records)-int(maxRecords):]
	}
	state.records = records
	return nil
}

// evtLatestRecordID returns the EventRecordID of the newest record or 0 for an empty event log
func evtLatestRecordID(channel string, renderContext windows.Handle, buffer *evtRenderBuffer) (uint64, error) {
	resultSet, err := evtQuery(channel, "*")
	if err != nil {
		return 0, err
	}
	defer evtClose(resultSet)

	events := make([]windows.Handle, 1)
	returned, err := evtNext(resultSet, events)
	if err != nil || returned == 0 {
		if errors.Is(err, errorNoMoreItems) {
			return 0, nil
		}
		return 0, err
	}
	defer evtClose(events[0])

	values, err := evtRenderValues(events[0], renderContext, buffer)
	if err != nil {
		return 0, err
	}
	return evtVariantUint64(values, evtSystemEventRecordID), nil
}

func evtReadRecords(ctx context.Context, channel, query string, renderContext windows.Handle, buffer *evtRenderBuffer, maxRecords int64) ([]*resultEvent, error) {
	resultSet, err := evtQuery(channel, query)
	if err != nil {
		return nil, err
	}
	defer evtClose(resultSet)

	var records []*resultEvent
	events := make([]windows.Handle, evtNextBatchSize)
	for int64(len(records)) < maxRecords {
		if ctx.Err() != nil {
			// Keep the records which were read so far, older records are skipped
			log.Warningln("Event Log: ", channel, ": timeout while reading records")
			break
		}

		returned, err := evtNext(resultSet, events)
		if err != nil {
			if errors.Is(err, errorNoMoreItems) {
				break
			}
			return nil, err
		}

		for _, event := range events[:returned] {
			if int64(len(records)) < maxRecords {
				if record, err := evtRenderRecord(event, renderContext, buffer); err == nil {
					records = append(records, record)
				} else {
					log.Errorln("Event Log: ", channel, ": could not render record: ", err)
				}
			}
			evtClose(event)
		}
	}
	return records, nil
}

func evtRenderRecord(event, renderContext windows.Handle, buffer *evtRenderBuffer) (*resultEvent, error) {
	values, err := evtRenderValues(event, renderContext, buffer)
	if err != nil {
		return nil, err
	}

	provider := evtVariantString(values, evtSystemProviderName)
	eventID := int64(evtVariantUint16(values, evtSystemEventID))
	task := int64(evtVariantUint16(values, evtSystemTask))
	timeCreated := time.Unix(0, (&windows.Filetime{
		LowDateTime:  uint32(evtVariantUint64(values, evtSystemTimeCreated)),
		HighDateTime: uint32(evtVariantUint64(values, evtSystemTimeCreated) >> 32),
	}).Nanoseconds()).Unix()

	record := &resultEvent{
		MachineName:    evtVariantString(values, evtSystemComputer),
		CategoryNumber: task,
		EventID:        eventID,
		EntryType:      evtEntryType(evtVariantUint8(values, evtSystemLevel), evtVariantUint64(values, evtSystemKeywords)),
		Source:         provider,
		TimeGenerated:  timeCreated,
		TimeWritten:    timeCreated,
		Index:          int64(evtVariantUint64(values, evtSystemEventRecordID)),
	}

	// The values point into the buffer, which gets reused by the following calls
	publisher := evtPublisherMetadata(provider)
	record.Message = evtFormatMessage(publisher, event, evtFormatMessageEvent)
	if record.Message == "" {
		record.Message = evtFallbackMessage(event, eventID, provider)
	}
	record.Message = truncateEventMessage(record.Message)

	record.Category = fmt.Sprintf("(%d)", task)
	if task != 0 {
		if category := evtFormatMessage(publisher, event, evtFormatMessageTask); category != "" {
			record.Category = category
		}
	}

	return record, nil
}

// evtEntryType maps the level and keywords to the EventLogEntryType of .NET
func evtEntryType(level uint8, keywords uint64) int64 {
	switch {
	case keywords&evtKeywordAuditFailure != 0:
		return entryTypeAuditFailure
	case keywords&evtKeywordAuditSuccess != 0:
		return entryTypeAuditSuccess
	}
	switch level {
	case 1, 2: // Critical, Error
		return entryTypeError
	case 3: // Warning
		return entryTypeWarning
	}
	// 0 = LogAlways, 4 = Information, 5 = Verbose
	return entryTypeInformation
}

func evtQuery(channel, query string) (windows.Handle, error) {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	// EvtQueryTolerateQueryErrors must not be used, as it also hides ERROR_EVT_CHANNEL_NOT_FOUND
	handle, _, err := procEvtQuery.Call(0, uintptr(unsafe.Pointer(channelPtr)), uintptr(unsafe.Pointer(queryPtr)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if handle == 0 {
		return 0, fmt.Errorf("EvtQuery: %s", err)
	}
	return windows.Handle(handle), nil
}

func evtNext(resultSet windows.Handle, events []windows.Handle) (uint32, error) {
	var returned uint32
	ok, _, err := procEvtNext.Call(uintptr(resultSet), uintptr(len(events)), uintptr(unsafe.Pointer(&events[0])),
		evtNextTimeoutMs, 0, uintptr(unsafe.Pointer(&returned)))
	if ok == 0 {
		return 0, err
	}
	return returned, nil
}

func evtClose(handle windows.Handle) {
	if handle != 0 {
		_, _, _ = procEvtClose.Call(uintptr(handle))
	}
}

// evtRenderValues renders the system properties of an event. The returned slice points into the buffer
func evtRenderValues(event, renderContext windows.Handle, buffer *evtRenderBuffer) ([]byte, error) {
	var used, propertyCount uint32
	data := buffer.bytes(1024)
	for attempt := 0; attempt < 2; attempt++ {
		ok, _, err := procEvtRender.Call(uintptr(renderContext), uintptr(event), evtRenderEventValues,
			uintptr(len(data)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propertyCount)))
		if ok != 0 {
			if propertyCount <= evtSystemComputer {
				return nil, fmt.Errorf("EvtRender returned only %d properties", propertyCount)
			}
			return data[:used], nil
		}
		if !errors.Is(err, errorInsufficientBuffr) {
			return nil, fmt.Errorf("EvtRender: %s", err)
		}
		data = buffer.bytes(used)
	}
	return nil, fmt.Errorf("EvtRender: buffer too small")
}

func evtVariantType(values []byte, index int) uint32 {
	return *(*uint32)(unsafe.Pointer(&values[index*evtVariantSize+evtVariantTypeOffset]))
}

func evtVariantUint64(values []byte, index int) uint64 {
	if evtVariantType(values, index) == evtVarTypeNull {
		return 0
	}
	return *(*uint64)(unsafe.Pointer(&values[index*evtVariantSize]))
}

func evtVariantUint16(values []byte, index int) uint16 {
	if evtVariantType(values, index) == evtVarTypeNull {
		return 0
	}
	return *(*uint16)(unsafe.Pointer(&values[index*evtVariantSize]))
}

func evtVariantUint8(values []byte, index int) uint8 {
	if evtVariantType(values, index) == evtVarTypeNull {
		return 0
	}
	return values[index*evtVariantSize]
}

func evtVariantString(values []byte, index int) string {
	if evtVariantType(values, index) == evtVarTypeNull {
		return ""
	}
	return windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&values[index*evtVariantSize])))
}

// evtPublisherMetadata returns the cached publisher metadata of a provider or 0 if not available
func evtPublisherMetadata(provider string) windows.Handle {
	if handle, ok := evtPublishers[provider]; ok {
		return handle
	}

	var handle uintptr
	if providerPtr, err := windows.UTF16PtrFromString(provider); err == nil && provider != "" {
		handle, _, _ = procEvtOpenPublisherMetadata.Call(0, uintptr(unsafe.Pointer(providerPtr)), 0, 0, 0)
	}
	// Also cache missing metadata, so it is not looked up for every record
	evtPublishers[provider] = windows.Handle(handle)
	return windows.Handle(handle)
}

// evtFormatMessage returns the formatted message or an empty string if the message could not be formatted
func evtFormatMessage(publisher, event windows.Handle, flags uintptr) string {
	if publisher == 0 {
		return ""
	}

	message := make([]uint16, 1024)
	for attempt := 0; attempt < 2; attempt++ {
		var used uint32
		ok, _, err := procEvtFormatMessage.Call(uintptr(publisher), uintptr(event), 0, 0, 0, flags,
			uintptr(len(message)), uintptr(unsafe.Pointer(&message[0])), uintptr(unsafe.Pointer(&used)))
		if ok != 0 {
			return strings.TrimSpace(windows.UTF16ToString(message))
		}
		switch {
		case errors.Is(err, errorInsufficientBuffr):
			message = make([]uint16, used)
		case errors.Is(err, windows.ERROR_EVT_UNRESOLVED_VALUE_INSERT), errors.Is(err, windows.ERROR_EVT_UNRESOLVED_PARAMETER_INSERT):
			// The message is formatted, but some placeholders could not be resolved
			return strings.TrimSpace(windows.UTF16ToString(message))
		default:
			// e.g. ERROR_EVT_MESSAGE_NOT_FOUND if the message DLL of the provider is missing
			return ""
		}
	}
	return ""
}

type evtEventXML struct {
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// evtFallbackMessage is used if the message could not be formatted. It contains the event data, like the Event Viewer shows it
func evtFallbackMessage(event windows.Handle, eventID int64, provider string) string {
	message := fmt.Sprintf("The description for Event ID %d from source %s cannot be found.", eventID, provider)

	var used, propertyCount uint32
	_, _, _ = procEvtRender.Call(0, uintptr(event), evtRenderEventXML, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propertyCount)))
	if used == 0 {
		return message
	}
	buffer := make([]uint16, used/2+1)
	ok, _, _ := procEvtRender.Call(0, uintptr(event), evtRenderEventXML, uintptr(len(buffer)*2), uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propertyCount)))
	if ok == 0 {
		return message
	}

	var data evtEventXML
	if err := xml.Unmarshal([]byte(windows.UTF16ToString(buffer)), &data); err != nil {
		return message
	}
	var values []string
	for _, value := range data.EventData.Data {
		if value.Name != "" {
			values = append(values, fmt.Sprintf("%s: %s", value.Name, value.Value))
		} else if value.Value != "" {
			values = append(values, value.Value)
		}
	}
	if len(values) > 0 {
		message += " Event data: " + strings.Join(values, ", ")
	}
	return message
}

func truncateEventMessage(message string) string {
	if len(message) <= evtMaxMessageLength {
		return message
	}
	return truncateLogLineTo(message, evtMaxMessageLength)
}

// closeEvtState releases the cached state, e.g. if the event log method or logs changed
func closeEvtState(keepChannels []string) {
	evtStatesMutex.Lock()
	defer evtStatesMutex.Unlock()

	keep := make(map[string]bool, len(keepChannels))
	for _, channel := range keepChannels {
		keep[channel] = true
	}
	for channel := range evtStates {
		if !keep[channel] {
			delete(evtStates, channel)
		}
	}
}
