package checks

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bougou/go-ipmi/pkg/client"
)

// The IPMI tests replay recordings of oitc-ipmi-dump. The go-ipmi client executes the test binary for every command
// ("ipmitool raw <netfn> <cmd> <data>"), which answers from the recording. SDR and SEL records are rebuilt from the
// recorded (partial) reads, so the agent can read them in a different order than the recording.

const ipmiReplayEnv = "OITC_IPMI_REPLAY"

func TestMain(m *testing.M) {
	if path := os.Getenv(ipmiReplayEnv); path != "" && len(os.Args) > 1 && os.Args[1] == "raw" {
		os.Exit(ipmiReplay(path, os.Args[2:]))
	}
	os.Exit(m.Run())
}

type ipmiRecordedExchange struct {
	NetFn    string `json:"netfn"`
	Cmd      string `json:"cmd"`
	Request  string `json:"request"`
	Code     string `json:"completion_code"`
	Response string `json:"response"`
}

type ipmiRecording struct {
	Exchanges []ipmiRecordedExchange `json:"exchanges"`
}

// ipmiReplayBMC answers the commands of a recording
type ipmiReplayBMC struct {
	responses  map[string][]byte // netfn|cmd|request => response
	codes      map[string]uint8  // netfn|cmd|request => completion code of a failed command
	sdrs       map[uint16][]byte
	sdrNext    map[uint16]uint16
	sdrFirst   uint16
	sels       map[uint16][]byte
	selNext    map[uint16]uint16
	selFirst   uint16
	selPresent bool
}

func newIpmiReplayBMC(recording *ipmiRecording) *ipmiReplayBMC {
	bmc := &ipmiReplayBMC{
		responses: map[string][]byte{},
		codes:     map[string]uint8{},
		sdrs:      map[uint16][]byte{},
		sdrNext:   map[uint16]uint16{},
		sels:      map[uint16][]byte{},
		selNext:   map[uint16]uint16{},
	}
	firstSet := map[string]bool{}
	for _, ex := range recording.Exchanges {
		netfn, _ := strconv.ParseUint(strings.TrimPrefix(ex.NetFn, "0x"), 16, 8)
		cmd, _ := strconv.ParseUint(strings.TrimPrefix(ex.Cmd, "0x"), 16, 8)
		request, _ := hex.DecodeString(ex.Request)
		response, _ := hex.DecodeString(ex.Response)
		code, _ := strconv.ParseUint(strings.TrimPrefix(ex.Code, "0x"), 16, 8)
		key := fmt.Sprintf("%02x|%02x|%s", netfn, cmd, ex.Request)

		// Get SDR (0x0a 0x23) and Get SEL Entry (0x0a 0x43): reservation, record id, offset, bytes to read
		if netfn == 0x0a && (cmd == 0x23 || cmd == 0x43) && len(request) == 6 {
			if code != 0 || len(response) < 2 {
				continue
			}
			recordID := binary.LittleEndian.Uint16(request[2:4])
			offset := int(request[4])
			next := binary.LittleEndian.Uint16(response[0:2])
			data := response[2:]
			records, nexts := bmc.sdrs, bmc.sdrNext
			if cmd == 0x43 {
				records, nexts = bmc.sels, bmc.selNext
				bmc.selPresent = true
			}
			if recordID == 0 && offset == 0 && len(data) >= 2 {
				// Record id 0 is the first record
				recordID = binary.LittleEndian.Uint16(data[0:2])
				if !firstSet[ex.Cmd] {
					firstSet[ex.Cmd] = true
					if cmd == 0x23 {
						bmc.sdrFirst = recordID
					} else {
						bmc.selFirst = recordID
					}
				}
			}
			record := records[recordID]
			if len(record) < offset+len(data) {
				record = append(record, make([]byte, offset+len(data)-len(record))...)
			}
			copy(record[offset:], data)
			records[recordID] = record
			nexts[recordID] = next
			continue
		}

		if code != 0 {
			if _, ok := bmc.responses[key]; !ok {
				bmc.codes[key] = uint8(code)
			}
			continue
		}
		if _, ok := bmc.responses[key]; !ok {
			bmc.responses[key] = response
			delete(bmc.codes, key)
		}
	}
	return bmc
}

// answer returns the response or the completion code of a command
func (bmc *ipmiReplayBMC) answer(netfn, cmd uint8, request []byte) ([]byte, uint8) {
	if netfn == 0x0a && (cmd == 0x23 || cmd == 0x43) && len(request) == 6 {
		records, nexts, first := bmc.sdrs, bmc.sdrNext, bmc.sdrFirst
		if cmd == 0x43 {
			if !bmc.selPresent {
				return nil, 0xcb
			}
			records, nexts, first = bmc.sels, bmc.selNext, bmc.selFirst
		}
		recordID := binary.LittleEndian.Uint16(request[2:4])
		if recordID == 0 {
			recordID = first
		}
		if recordID == 0xffff {
			// The last record
			for id, next := range nexts {
				if next == 0xffff {
					recordID = id
				}
			}
		}
		record, ok := records[recordID]
		if !ok {
			return nil, 0xcb
		}
		offset := int(request[4])
		count := int(request[5])
		if offset > len(record) {
			return nil, 0xc9
		}
		end := len(record)
		if count != 0xff && offset+count < end {
			end = offset + count
		}
		response := make([]byte, 2, 2+end-offset)
		binary.LittleEndian.PutUint16(response, nexts[recordID])
		return append(response, record[offset:end]...), 0
	}

	key := fmt.Sprintf("%02x|%02x|%s", netfn, cmd, hex.EncodeToString(request))
	if response, ok := bmc.responses[key]; ok {
		return response, 0
	}
	if code, ok := bmc.codes[key]; ok {
		return nil, code
	}
	// Reservations are not bound to a request
	if netfn == 0x0a && (cmd == 0x22 || cmd == 0x42) || netfn == 0x04 && cmd == 0x22 {
		for k, response := range bmc.responses {
			if strings.HasPrefix(k, fmt.Sprintf("%02x|%02x|", netfn, cmd)) {
				return response, 0
			}
		}
	}
	return nil, 0xc1
}

// ipmiReplay executes a single command of the go-ipmi tool interface
func ipmiReplay(path string, args []string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var recording ipmiRecording
	if err := json.Unmarshal(data, &recording); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	msg := make([]byte, 0, len(args))
	for _, arg := range args {
		value, err := strconv.ParseUint(strings.TrimPrefix(arg, "0x"), 16, 8)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		msg = append(msg, uint8(value))
	}
	if len(msg) < 2 {
		return 1
	}
	response, code := newIpmiReplayBMC(&recording).answer(msg[0], msg[1], msg[2:])
	if code != 0 {
		fmt.Fprintf(os.Stderr, "Unable to send RAW command (channel=0x0 netfn=0x%x lun=0x0 cmd=0x%x rsp=0x%02x): replay\n", msg[0], msg[1], code)
		return 1
	}
	parts := make([]string, len(response))
	for i, b := range response {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	fmt.Println(strings.Join(parts, " "))
	return 0
}

// newIpmiReplayClient returns a client which replays the given recording of testdata/ipmi or an absolute path
func newIpmiReplayClient(t *testing.T, name string) *client.Client {
	t.Helper()
	path := name
	if !filepath.IsAbs(name) {
		dir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(dir, "testdata", "ipmi", name)
	}
	t.Setenv(ipmiReplayEnv, path)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.NewToolClient(executable)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
