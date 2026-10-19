package checks

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/yusufpapurcu/wmi"
)

// Win32_EncryptableVolume of root\CIMV2\Security\MicrosoftVolumeEncryption (requires admin rights)
// https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume
// nolint:underscore
type Win32_EncryptableVolume struct {
	DriveLetter      string
	ProtectionStatus uint32 // 0 = off (also if suspended), 1 = on, 2 = unknown (locked)
	ConversionStatus uint32 // 0 = fully decrypted, 1 = fully encrypted, 2 = encryption in progress, ...
	EncryptionMethod uint32
	VolumeType       uint32 // 0 = operating system, 1 = fixed data, 2 = portable (Windows 8 or newer)
}

type resultBitLockerVolume struct {
	Drive            string `json:"drive"`             // e.g.: C:
	VolumeType       string `json:"volume_type"`       // os, fixed or portable
	Protection       string `json:"protection"`        // on, off or unknown (e.g. locked)
	Conversion       string `json:"conversion"`        // e.g.: fully_encrypted, encryption_in_progress
	EncryptionMethod string `json:"encryption_method"` // e.g.: XTS-AES 128
}

type resultBitLocker struct {
	Available bool                     `json:"available"` // false if BitLocker is not installed (e.g. Windows Home)
	Volumes   []*resultBitLockerVolume `json:"volumes"`
}

var bitLockerProtection = map[uint32]string{0: "off", 1: "on", 2: "unknown"}

var bitLockerConversion = map[uint32]string{
	0: "fully_decrypted",
	1: "fully_encrypted",
	2: "encryption_in_progress",
	3: "decryption_in_progress",
	4: "encryption_paused",
	5: "decryption_paused",
}

var bitLockerVolumeType = map[uint32]string{0: "os", 1: "fixed", 2: "portable"}

var bitLockerEncryptionMethod = map[uint32]string{
	0: "none",
	1: "AES 128 with diffuser",
	2: "AES 256 with diffuser",
	3: "AES 128",
	4: "AES 256",
	5: "hardware encryption",
	6: "XTS-AES 128",
	7: "XTS-AES 256",
}

// The BitLocker state rarely changes, but the WMI query is slow: without admin rights it takes 5 seconds until access
// is denied, which blocks all other WMI queries of the agent
const bitLockerCacheDuration = 5 * time.Minute

var bitLockerCache struct {
	sync.Mutex
	result  *resultBitLocker
	err     error
	expires time.Time
}

func getBitLocker() (*resultBitLocker, error) {
	bitLockerCache.Lock()
	defer bitLockerCache.Unlock()
	if time.Now().Before(bitLockerCache.expires) {
		return bitLockerCache.result, bitLockerCache.err
	}
	bitLockerCache.result, bitLockerCache.err = queryBitLocker()
	bitLockerCache.expires = time.Now().Add(bitLockerCacheDuration)
	return bitLockerCache.result, bitLockerCache.err
}

func queryBitLocker() (*resultBitLocker, error) {
	var dst []Win32_EncryptableVolume
	err := wmi.QueryNamespace("SELECT DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod, VolumeType FROM Win32_EncryptableVolume",
		&dst, `root\CIMV2\Security\MicrosoftVolumeEncryption`)
	if err != nil {
		var fieldMismatch *wmi.ErrFieldMismatch
		if !errors.As(err, &fieldMismatch) {
			if isWMINotFound(err) {
				return &resultBitLocker{Available: false, Volumes: []*resultBitLockerVolume{}}, nil
			}
			// e.g. access denied without admin rights
			return nil, err
		}
	}
	return bitLockerResult(dst), nil
}

func bitLockerResult(volumes []Win32_EncryptableVolume) *resultBitLocker {
	result := &resultBitLocker{Available: true, Volumes: []*resultBitLockerVolume{}}
	for _, volume := range volumes {
		if volume.DriveLetter == "" {
			// Volumes without drive letter, e.g. the recovery partition
			continue
		}
		result.Volumes = append(result.Volumes, &resultBitLockerVolume{
			Drive:            volume.DriveLetter,
			VolumeType:       mapLookup(bitLockerVolumeType, volume.VolumeType),
			Protection:       mapLookup(bitLockerProtection, volume.ProtectionStatus),
			Conversion:       mapLookup(bitLockerConversion, volume.ConversionStatus),
			EncryptionMethod: mapLookup(bitLockerEncryptionMethod, volume.EncryptionMethod),
		})
	}
	sort.Slice(result.Volumes, func(i, j int) bool {
		return result.Volumes[i].Drive < result.Volumes[j].Drive
	})
	return result
}

func mapLookup(values map[uint32]string, key uint32) string {
	if value, ok := values[key]; ok {
		return value
	}
	return "unknown"
}
