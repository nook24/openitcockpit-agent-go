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
	// pvesh needs about half a second of CPU time per call, so the result is cached
	proxmoxCacheDuration  = 2 * time.Minute
	proxmoxCommandTimeout = 20 * time.Second
	// Number of the latest backup tasks of the node
	proxmoxBackupTaskLimit = 50
)

var (
	proxmoxCacheMutex sync.Mutex
	proxmoxCache      map[string]interface{}
	proxmoxCacheTime  time.Time
)

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
	proxmoxCacheMutex.Lock()
	defer proxmoxCacheMutex.Unlock()

	if proxmoxCache != nil && time.Since(proxmoxCacheTime) < proxmoxCacheDuration {
		return proxmoxCache, nil
	}

	pvesh := c.pvesh
	if pvesh == "" {
		pvesh = "pvesh"
	}

	// The cluster status contains the name of the local node, which is required for the other queries
	statusOutput, err := runPvesh(ctx, pvesh, "/cluster/status")
	if err != nil {
		return nil, err
	}
	cluster, localNode, err := parseProxmoxClusterStatus(statusOutput)
	if err != nil {
		return nil, err
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

	// The other parts are queried in parallel. Every part can fail on its own
	queries := map[string][]string{
		"ha":            {"/cluster/ha/status/current"},
		"storages":      {fmt.Sprintf("/nodes/%s/storage", localNode)},
		"guests":        {"/cluster/resources", "--type", "vm"},
		"tasks":         {fmt.Sprintf("/nodes/%s/tasks", localNode), "--typefilter", "vzdump", "--limit", strconv.Itoa(proxmoxBackupTaskLimit)},
		"not_backed_up": {"/cluster/backup-info/not-backed-up"},
		"replication":   {fmt.Sprintf("/nodes/%s/replication", localNode)},
	}
	outputs := map[string][]byte{}
	errs := map[string]error{}
	var mutex sync.Mutex
	var wg sync.WaitGroup
	for name, args := range queries {
		wg.Add(1)
		go func(name string, args []string) {
			defer wg.Done()
			output, err := runPvesh(ctx, pvesh, args...)
			mutex.Lock()
			defer mutex.Unlock()
			outputs[name], errs[name] = output, err
		}(name, args)
	}
	wg.Wait()

	setPart := func(name string, value interface{}, err error) {
		if err != nil {
			result[name] = map[string]string{"error": err.Error()}
			return
		}
		result[name] = value
	}

	ha, err := parseProxmoxHa(outputs["ha"], errs["ha"])
	setPart("ha", ha, err)

	storages, err := parseProxmoxStorages(outputs["storages"], errs["storages"])
	setPart("storages", storages, err)

	guests, err := parseProxmoxGuests(outputs["guests"], errs["guests"])
	setPart("guests", guests, err)

	backups, err := parseProxmoxBackups(outputs["tasks"], errs["tasks"], outputs["not_backed_up"], errs["not_backed_up"], guests, localNode)
	setPart("backups", backups, err)

	replication, err := parseProxmoxReplication(outputs["replication"], errs["replication"])
	setPart("replication", replication, err)

	proxmoxCache, proxmoxCacheTime = result, time.Now()
	return result, nil
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

	cmdArgs := append([]string{"get"}, args...)
	cmdArgs = append(cmdArgs, "--output-format", "json")
	output, err := exec.CommandContext(ctx, pvesh, cmdArgs...).Output()
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

func parseProxmoxStorages(data []byte, err error) ([]*resultProxmoxStorage, error) {
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Storage      string      `json:"storage"`
		Type         string      `json:"type"`
		Content      string      `json:"content"`
		Enabled      proxmoxBool `json:"enabled"`
		Active       proxmoxBool `json:"active"`
		Shared       proxmoxBool `json:"shared"`
		Total        int64       `json:"total"`
		Used         int64       `json:"used"`
		Avail        int64       `json:"avail"`
		UsedFraction float64     `json:"used_fraction"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("could not parse storage status: %s", err)
	}

	storages := make([]*resultProxmoxStorage, 0, len(entries))
	for _, entry := range entries {
		storage := &resultProxmoxStorage{
			Storage:     entry.Storage,
			Type:        entry.Type,
			Content:     entry.Content,
			Enabled:     bool(entry.Enabled),
			Active:      bool(entry.Active),
			Shared:      bool(entry.Shared),
			Total:       entry.Total,
			Used:        entry.Used,
			Available:   entry.Avail,
			UsedPercent: entry.UsedFraction * 100,
		}
		if storage.UsedPercent == 0 && storage.Total > 0 {
			storage.UsedPercent = float64(storage.Used) / float64(storage.Total) * 100
		}
		storages = append(storages, storage)
	}
	return storages, nil
}

func parseProxmoxGuests(data []byte, err error) ([]*resultProxmoxGuest, error) {
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Vmid     int64       `json:"vmid"`
		Name     string      `json:"name"`
		Type     string      `json:"type"`
		Node     string      `json:"node"`
		Status   string      `json:"status"`
		Uptime   int64       `json:"uptime"`
		Template proxmoxBool `json:"template"`
		Lock     string      `json:"lock"`
		HaState  string      `json:"hastate"`
		Tags     string      `json:"tags"`
		CPU      float64     `json:"cpu"`
		MaxCPU   int64       `json:"maxcpu"`
		Mem      int64       `json:"mem"`
		MaxMem   int64       `json:"maxmem"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("could not parse /cluster/resources: %s", err)
	}

	// All guests of the cluster, so a guest can be monitored independent of the node it was migrated to
	guests := []*resultProxmoxGuest{}
	for _, entry := range entries {
		if entry.Type != "qemu" && entry.Type != "lxc" {
			continue
		}
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
	}
	return guests, nil
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
