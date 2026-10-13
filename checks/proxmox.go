package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const (
	proxmoxConfigPath = "/etc/pve"
	// pvesh needs up to 1.5 seconds of CPU time per call on small systems, so the data is collected in the background:
	// cluster status, HA and resources every 2 minutes, backups and replication every 10 minutes
	proxmoxCoreInterval   = 2 * time.Minute
	proxmoxSlowInterval   = 10 * time.Minute
	proxmoxCommandTimeout = 30 * time.Second
	// The background collector stops if the check was not executed for this time (e.g. disabled by a reload)
	proxmoxIdleTimeout = 10 * time.Minute
	// Number of the latest backup tasks of the node
	proxmoxBackupTaskLimit = 50
)

// proxmoxCollector collects the data in the background, so the slow pvesh calls do not delay the other checks
type proxmoxCollector struct {
	mutex      sync.Mutex
	pvesh      string
	generation int // Incremented by reset, so an old background goroutine stops
	running    bool
	lastAccess time.Time

	localNode string
	core      map[string]interface{} // node, cluster, ha, guests, storages, collected_at
	coreErr   error                  // The cluster status is not available (e.g. pve-cluster is not running)
	coreTime  time.Time
	guests    []*resultProxmoxGuest
	slow      map[string]interface{} // backups, replication
	slowTime  time.Time
}

var proxmoxState = &proxmoxCollector{}

// resetProxmoxCollector discards all collected data and stops the background goroutine
func resetProxmoxCollector() {
	proxmoxState.mutex.Lock()
	defer proxmoxState.mutex.Unlock()
	proxmoxState.generation++
	proxmoxState.running = false
	proxmoxState.core, proxmoxState.coreErr, proxmoxState.slow = nil, nil, nil
	proxmoxState.coreTime, proxmoxState.slowTime = time.Time{}, time.Time{}
}

// CheckProxmox gathers the state of a Proxmox VE node and its cluster with pvesh
type CheckProxmox struct {
	// can be changed by tests
	pvesh string
}

// Name will be used in the response as check name
func (c *CheckProxmox) Name() string {
	return "proxmox"
}

type resultProxmoxNode struct {
	Name   string `json:"name"`
	Online bool   `json:"online"`
	Local  bool   `json:"local"`
	IP     string `json:"ip"`
}

type resultProxmoxCluster struct {
	Clustered   bool                 `json:"clustered"` // false for a single node without cluster
	Name        string               `json:"name"`
	Quorate     bool                 `json:"quorate"`
	NodesTotal  int64                `json:"nodes_total"`
	NodesOnline int64                `json:"nodes_online"`
	Nodes       []*resultProxmoxNode `json:"nodes"`
}

type resultProxmoxHaService struct {
	Sid          string `json:"sid"`  // e.g.: vm:100
	Node         string `json:"node"` // Node of the service
	State        string `json:"state"`
	RequestState string `json:"request_state"` // e.g.: started, stopped, disabled, ignored
	Status       string `json:"status"`
}

type resultProxmoxHa struct {
	Quorate  bool                      `json:"quorate"`
	Master   string                    `json:"master"`   // e.g.: pve1 (active, Mon Oct 13 10:00:00 2025)
	Lrms     map[string]string         `json:"lrms"`     // Local resource manager per node, e.g.: pve1 (active, ...)
	Services []*resultProxmoxHaService `json:"services"` // HA resources of the whole cluster
}

type resultProxmoxStorage struct {
	Storage     string  `json:"storage"`
	Type        string  `json:"type"` // e.g.: dir, lvmthin, zfspool, rbd, nfs, cephfs, pbs
	Content     string  `json:"content"`
	Enabled     bool    `json:"enabled"`
	Active      bool    `json:"active"` // false if an enabled storage is not available (e.g. NFS server down)
	Shared      bool    `json:"shared"`
	Total       int64   `json:"total"`
	Used        int64   `json:"used"`
	Available   int64   `json:"available"`
	UsedPercent float64 `json:"used_percent"`
}

type resultProxmoxGuest struct {
	Vmid     int64   `json:"vmid"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`   // qemu or lxc
	Node     string  `json:"node"`   // Node the guest is running on
	Status   string  `json:"status"` // running, stopped, paused
	Uptime   int64   `json:"uptime"`
	Template bool    `json:"template"`
	Lock     string  `json:"lock"` // e.g.: backup, migrate, snapshot
	HaState  string  `json:"ha_state"`
	Tags     string  `json:"tags"`
	CPU      float64 `json:"cpu"` // Usage of maxcpu, 0 to 1
	MaxCPU   int64   `json:"max_cpu"`
	Memory   int64   `json:"memory"`
	MaxMem   int64   `json:"max_memory"`
}

type resultProxmoxBackupTask struct {
	Upid      string `json:"upid"`
	ID        string `json:"id"` // vmid for backups of a single guest, empty for backup jobs
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"` // 0 if the task is running
	Status    string `json:"status"`   // OK, WARNINGS: n, job errors, ... empty if the task is running
	User      string `json:"user"`
}

type resultProxmoxGuestRef struct {
	Vmid int64  `json:"vmid"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type resultProxmoxBackups struct {
	Tasks       []*resultProxmoxBackupTask `json:"tasks"`         // Latest vzdump tasks of the node, newest first
	NotBackedUp []*resultProxmoxGuestRef   `json:"not_backed_up"` // Guests of the node which are not part of any backup job
}

type resultProxmoxReplication struct {
	ID        string  `json:"id"` // e.g.: 100-0
	Guest     int64   `json:"guest"`
	Target    string  `json:"target"`
	Schedule  string  `json:"schedule"`
	LastSync  int64   `json:"last_sync"`
	NextSync  int64   `json:"next_sync"`
	Duration  float64 `json:"duration"`
	FailCount int64   `json:"fail_count"`
	Error     string  `json:"error"`
	Disabled  bool    `json:"disabled"`
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckProxmox) Run(ctx context.Context) (interface{}, error) {
	pvesh := c.pvesh
	if pvesh == "" {
		pvesh = "pvesh"
	}

	state := proxmoxState
	state.mutex.Lock()
	defer state.mutex.Unlock()
	state.pvesh = pvesh
	state.lastAccess = time.Now()

	// The first run collects the core data synchronously, all following runs return the data of the background collector.
	// Backups and replication are collected by the background collector right after the first run
	if state.core == nil {
		state.mutex.Unlock()
		core, guests, localNode, err := collectProxmoxCore(ctx, pvesh)
		state.mutex.Lock()
		state.storeCore(core, guests, localNode, err)
	}

	if !state.running {
		state.running = true
		go state.collect(state.generation)
	}

	if state.coreErr != nil {
		return nil, state.coreErr
	}
	result := make(map[string]interface{}, len(state.core)+len(state.slow))
	for key, value := range state.core {
		result[key] = value
	}
	for key, value := range state.slow {
		result[key] = value
	}
	return result, nil
}

func (s *proxmoxCollector) storeCore(core map[string]interface{}, guests []*resultProxmoxGuest, localNode string, err error) {
	s.coreTime = time.Now()
	s.coreErr = err
	if err != nil {
		return
	}
	s.core, s.guests, s.localNode = core, guests, localNode
}

// collect runs in the background and refreshes the data
func (s *proxmoxCollector) collect(generation int) {
	for first := true; ; first = false {
		if !first {
			time.Sleep(15 * time.Second)
		}

		s.mutex.Lock()
		if s.generation != generation || time.Since(s.lastAccess) > proxmoxIdleTimeout {
			if s.generation == generation {
				s.running = false
			}
			s.mutex.Unlock()
			return
		}
		pvesh := s.pvesh
		refreshCore := time.Since(s.coreTime) >= proxmoxCoreInterval
		refreshSlow := s.coreErr == nil && time.Since(s.slowTime) >= proxmoxSlowInterval
		s.mutex.Unlock()

		ctx := context.Background()
		if refreshCore {
			core, guests, localNode, err := collectProxmoxCore(ctx, pvesh)
			s.mutex.Lock()
			if s.generation == generation {
				s.storeCore(core, guests, localNode, err)
			}
			s.mutex.Unlock()
		}
		if refreshSlow {
			s.mutex.Lock()
			localNode, guests := s.localNode, s.guests
			s.mutex.Unlock()
			slow := collectProxmoxSlow(ctx, pvesh, localNode, guests)
			s.mutex.Lock()
			if s.generation == generation {
				s.slow, s.slowTime = slow, time.Now()
			}
			s.mutex.Unlock()
		}
	}
}

// collectProxmoxCore queries the cluster status, HA status and the resources of the cluster (guests and storages)
func collectProxmoxCore(ctx context.Context, pvesh string) (map[string]interface{}, []*resultProxmoxGuest, string, error) {
	statusOutput, err := runPvesh(ctx, pvesh, "/cluster/status")
	if err != nil {
		return nil, nil, "", err
	}
	cluster, localNode, err := parseProxmoxClusterStatus(statusOutput)
	if err != nil {
		return nil, nil, "", err
	}
	if localNode == "" {
		if hostname, err := os.Hostname(); err == nil {
			localNode = strings.Split(hostname, ".")[0]
		}
	}

	result := map[string]interface{}{
		"node":         localNode,
		"collected_at": time.Now().Unix(),
		"cluster":      cluster,
	}
	setProxmoxPart(result, "ha", func() (interface{}, error) {
		output, err := runPvesh(ctx, pvesh, "/cluster/ha/status/current")
		return parseProxmoxHa(output, err)
	})

	// The resources contain the guests of the cluster and the storages of all nodes, which saves pvesh calls
	output, err := runPvesh(ctx, pvesh, "/cluster/resources")
	guests, storages, err := parseProxmoxResources(output, err, localNode)
	setProxmoxPart(result, "guests", func() (interface{}, error) { return guests, err })
	setProxmoxPart(result, "storages", func() (interface{}, error) { return storages, err })
	return result, guests, localNode, nil
}

// collectProxmoxSlow queries the backup tasks, the guests without backup job and the replication jobs
func collectProxmoxSlow(ctx context.Context, pvesh, localNode string, guests []*resultProxmoxGuest) map[string]interface{} {
	result := map[string]interface{}{}
	setProxmoxPart(result, "backups", func() (interface{}, error) {
		tasks, tasksErr := runPvesh(ctx, pvesh, fmt.Sprintf("/nodes/%s/tasks", localNode), "--typefilter", "vzdump", "--limit", strconv.Itoa(proxmoxBackupTaskLimit))
		notBackedUp, notBackedUpErr := runPvesh(ctx, pvesh, "/cluster/backup-info/not-backed-up")
		return parseProxmoxBackups(tasks, tasksErr, notBackedUp, notBackedUpErr, guests, localNode)
	})
	setProxmoxPart(result, "replication", func() (interface{}, error) {
		output, err := runPvesh(ctx, pvesh, fmt.Sprintf("/nodes/%s/replication", localNode))
		return parseProxmoxReplication(output, err)
	})
	return result
}

// setProxmoxPart stores a part of the result or its error. Every part can fail on its own
func setProxmoxPart(result map[string]interface{}, name string, get func() (interface{}, error)) {
	value, err := get()
	if err != nil {
		result[name] = map[string]string{"error": err.Error()}
		return
	}
	result[name] = value
}

// Configure the command or return false if the command was disabled
func (c *CheckProxmox) Configure(config *config.Configuration) (bool, error) {
	if !config.Proxmox {
		return false, nil
	}
	// Only enable the check on Proxmox VE nodes
	if _, err := exec.LookPath("pvesh"); err != nil {
		return false, nil
	}
	if _, err := os.Stat(proxmoxConfigPath); err != nil {
		return false, nil
	}
	return true, nil
}

func runPvesh(ctx context.Context, pvesh string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, proxmoxCommandTimeout)
	defer cancel()

	pvesh, err := exec.LookPath(pvesh)
	if err != nil {
		return nil, err
	}

	cmdArgs := append([]string{"get"}, args...)
	cmdArgs = append(cmdArgs, "--output-format", "json")
	// Low priority, as monitoring must not slow down the virtual machines
	name := pvesh
	if nice, err := exec.LookPath("nice"); err == nil {
		name = nice
		cmdArgs = append([]string{"-n", "10", pvesh}, cmdArgs...)
	}
	output, err := exec.CommandContext(ctx, name, cmdArgs...).Output()
	if err != nil {
		var stderr string
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(exitError.Stderr))
		}
		return nil, fmt.Errorf("pvesh get %s failed: %s: %s", args[0], err, stderr)
	}
	return output, nil
}

// proxmoxBool converts the 0/1 values of the Proxmox API
type proxmoxBool bool

func (b *proxmoxBool) UnmarshalJSON(data []byte) error {
	value := strings.Trim(string(data), `"`)
	*b = proxmoxBool(value == "1" || value == "true")
	return nil
}

// proxmoxString accepts strings and numbers, as the Proxmox API is not consistent (e.g. task ids)
type proxmoxString string

func (s *proxmoxString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = ""
		return nil
	}
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = proxmoxString(str)
		return nil
	}
	*s = proxmoxString(strings.Trim(string(data), `"`))
	return nil
}

func parseProxmoxClusterStatus(data []byte) (*resultProxmoxCluster, string, error) {
	var entries []struct {
		Type    string        `json:"type"`
		Name    string        `json:"name"`
		Quorate proxmoxBool   `json:"quorate"`
		Nodes   int64         `json:"nodes"`
		Online  proxmoxBool   `json:"online"`
		Local   proxmoxBool   `json:"local"`
		IP      proxmoxString `json:"ip"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, "", fmt.Errorf("could not parse /cluster/status: %s", err)
	}

	cluster := &resultProxmoxCluster{Nodes: []*resultProxmoxNode{}}
	localNode := ""
	for _, entry := range entries {
		switch entry.Type {
		case "cluster":
			cluster.Clustered = true
			cluster.Name = entry.Name
			cluster.Quorate = bool(entry.Quorate)
			cluster.NodesTotal = entry.Nodes
		case "node":
			node := &resultProxmoxNode{Name: entry.Name, Online: bool(entry.Online), Local: bool(entry.Local), IP: string(entry.IP)}
			cluster.Nodes = append(cluster.Nodes, node)
			if node.Online {
				cluster.NodesOnline++
			}
			if node.Local {
				localNode = node.Name
			}
		}
	}
	if !cluster.Clustered {
		// A single node without cluster always has quorum
		cluster.Quorate = true
		cluster.NodesTotal = int64(len(cluster.Nodes))
	}
	return cluster, localNode, nil
}

func parseProxmoxHa(data []byte, err error) (*resultProxmoxHa, error) {
	if err != nil {
		return nil, err
	}
	var entries []struct {
		ID           string        `json:"id"`
		Type         string        `json:"type"`
		Node         string        `json:"node"`
		Status       string        `json:"status"`
		Quorate      proxmoxBool   `json:"quorate"`
		Sid          string        `json:"sid"`
		State        proxmoxString `json:"state"`
		RequestState proxmoxString `json:"request_state"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("could not parse /cluster/ha/status/current: %s", err)
	}

	ha := &resultProxmoxHa{Lrms: map[string]string{}, Services: []*resultProxmoxHaService{}}
	for _, entry := range entries {
		switch entry.Type {
		case "quorum":
			ha.Quorate = bool(entry.Quorate)
		case "master":
			ha.Master = entry.Status
		case "lrm":
			ha.Lrms[entry.Node] = entry.Status
		case "service":
			ha.Services = append(ha.Services, &resultProxmoxHaService{
				Sid:          entry.Sid,
				Node:         entry.Node,
				State:        string(entry.State),
				RequestState: string(entry.RequestState),
				Status:       entry.Status,
			})
		}
	}
	return ha, nil
}

// parseProxmoxResources returns the guests of the cluster and the storages of the local node of /cluster/resources.
// The storage status comes from the status cache of Proxmox (pvestatd), so no storage gets activated by the query
func parseProxmoxResources(data []byte, err error, localNode string) ([]*resultProxmoxGuest, []*resultProxmoxStorage, error) {
	if err != nil {
		return nil, nil, err
	}
	var entries []struct {
		Type     string      `json:"type"`
		Node     string      `json:"node"`
		Status   string      `json:"status"`
		Vmid     int64       `json:"vmid"`
		Name     string      `json:"name"`
		Uptime   int64       `json:"uptime"`
		Template proxmoxBool `json:"template"`
		Lock     string      `json:"lock"`
		HaState  string      `json:"hastate"`
		Tags     string      `json:"tags"`
		CPU      float64     `json:"cpu"`
		MaxCPU   int64       `json:"maxcpu"`
		Mem      int64       `json:"mem"`
		MaxMem   int64       `json:"maxmem"`
		// Storages
		Storage    string      `json:"storage"`
		PluginType string      `json:"plugintype"`
		Content    string      `json:"content"`
		Shared     proxmoxBool `json:"shared"`
		Disk       int64       `json:"disk"`
		MaxDisk    int64       `json:"maxdisk"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, nil, fmt.Errorf("could not parse /cluster/resources: %s", err)
	}

	// All guests of the cluster, so a guest can be monitored independent of the node it was migrated to
	guests := []*resultProxmoxGuest{}
	storages := []*resultProxmoxStorage{}
	for _, entry := range entries {
		switch entry.Type {
		case "qemu", "lxc":
			guests = append(guests, &resultProxmoxGuest{
				Vmid:     entry.Vmid,
				Name:     entry.Name,
				Type:     entry.Type,
				Node:     entry.Node,
				Status:   entry.Status,
				Uptime:   entry.Uptime,
				Template: bool(entry.Template),
				Lock:     entry.Lock,
				HaState:  entry.HaState,
				Tags:     entry.Tags,
				CPU:      entry.CPU,
				MaxCPU:   entry.MaxCPU,
				Memory:   entry.Mem,
				MaxMem:   entry.MaxMem,
			})
		case "storage":
			// Only the storages of this node, disabled storages are not part of the resources
			if localNode != "" && entry.Node != localNode {
				continue
			}
			storage := &resultProxmoxStorage{
				Storage: entry.Storage,
				Type:    entry.PluginType,
				Content: entry.Content,
				Enabled: true,
				Active:  entry.Status == "available",
				Shared:  bool(entry.Shared),
				Total:   entry.MaxDisk,
				Used:    entry.Disk,
			}
			if storage.Total > 0 {
				storage.Available = storage.Total - storage.Used
				storage.UsedPercent = float64(storage.Used) / float64(storage.Total) * 100
			}
			storages = append(storages, storage)
		}
	}
	return guests, storages, nil
}

func parseProxmoxBackups(tasksData []byte, tasksErr error, notBackedUpData []byte, notBackedUpErr error, guests []*resultProxmoxGuest, localNode string) (*resultProxmoxBackups, error) {
	if tasksErr != nil {
		return nil, tasksErr
	}
	var tasks []struct {
		Upid      string        `json:"upid"`
		ID        proxmoxString `json:"id"`
		StartTime int64         `json:"starttime"`
		EndTime   int64         `json:"endtime"`
		Status    string        `json:"status"`
		User      string        `json:"user"`
	}
	if err := json.Unmarshal(tasksData, &tasks); err != nil {
		return nil, fmt.Errorf("could not parse backup tasks: %s", err)
	}

	backups := &resultProxmoxBackups{
		Tasks:       make([]*resultProxmoxBackupTask, 0, len(tasks)),
		NotBackedUp: []*resultProxmoxGuestRef{},
	}
	for _, task := range tasks {
		backups.Tasks = append(backups.Tasks, &resultProxmoxBackupTask{
			Upid:      task.Upid,
			ID:        string(task.ID),
			StartTime: task.StartTime,
			EndTime:   task.EndTime,
			Status:    task.Status,
			User:      task.User,
		})
	}

	// Optional, the endpoint exists since Proxmox VE 6.4
	if notBackedUpErr == nil {
		var notBackedUp []*resultProxmoxGuestRef
		if err := json.Unmarshal(notBackedUpData, &notBackedUp); err == nil {
			// Only guests of this node
			local := map[int64]bool{}
			for _, guest := range guests {
				if !guest.Template && (localNode == "" || guest.Node == localNode) {
					local[guest.Vmid] = true
				}
			}
			for _, guest := range notBackedUp {
				if guests == nil || local[guest.Vmid] {
					backups.NotBackedUp = append(backups.NotBackedUp, guest)
				}
			}
		}
	}
	return backups, nil
}

func parseProxmoxReplication(data []byte, err error) ([]*resultProxmoxReplication, error) {
	if err != nil {
		return nil, err
	}
	var entries []struct {
		ID        string      `json:"id"`
		Guest     int64       `json:"guest"`
		Target    string      `json:"target"`
		Schedule  string      `json:"schedule"`
		LastSync  int64       `json:"last_sync"`
		NextSync  int64       `json:"next_sync"`
		Duration  float64     `json:"duration"`
		FailCount int64       `json:"fail_count"`
		Error     string      `json:"error"`
		Disable   proxmoxBool `json:"disable"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("could not parse replication status: %s", err)
	}

	jobs := make([]*resultProxmoxReplication, 0, len(entries))
	for _, entry := range entries {
		jobs = append(jobs, &resultProxmoxReplication{
			ID:        entry.ID,
			Guest:     entry.Guest,
			Target:    entry.Target,
			Schedule:  entry.Schedule,
			LastSync:  entry.LastSync,
			NextSync:  entry.NextSync,
			Duration:  entry.Duration,
			FailCount: entry.FailCount,
			Error:     entry.Error,
			Disabled:  bool(entry.Disable),
		})
	}
	return jobs, nil
}
