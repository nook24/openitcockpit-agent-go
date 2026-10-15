package checks

import (
	"context"
	"testing"
)

func TestBitLockerResult(t *testing.T) {
	result := bitLockerResult([]Win32_EncryptableVolume{
		{DriveLetter: "D:", ProtectionStatus: 0, ConversionStatus: 0, EncryptionMethod: 0, VolumeType: 1},
		{DriveLetter: "C:", ProtectionStatus: 1, ConversionStatus: 1, EncryptionMethod: 6, VolumeType: 0},
		{DriveLetter: "", ProtectionStatus: 0, VolumeType: 0},
		{DriveLetter: "E:", ProtectionStatus: 0, ConversionStatus: 2, EncryptionMethod: 7, VolumeType: 2},
	})
	if !result.Available || len(result.Volumes) != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if v := result.Volumes[0]; v.Drive != "C:" || v.VolumeType != "os" || v.Protection != "on" || v.Conversion != "fully_encrypted" || v.EncryptionMethod != "XTS-AES 128" {
		t.Errorf("unexpected C: %+v", v)
	}
	if v := result.Volumes[1]; v.Drive != "D:" || v.Protection != "off" || v.Conversion != "fully_decrypted" || v.EncryptionMethod != "none" {
		t.Errorf("unexpected D: %+v", v)
	}
	if v := result.Volumes[2]; v.VolumeType != "portable" || v.Conversion != "encryption_in_progress" {
		t.Errorf("unexpected E: %+v", v)
	}
}

// Without admin rights only the BitLocker part reports an error, the other parts of the security check work
func TestSecurityCheckBitLockerPart(t *testing.T) {
	r, err := (&CheckSecurity{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := r.(map[string]interface{})
	switch bitlocker := result["bitlocker"].(type) {
	case *resultBitLocker:
		t.Logf("BitLocker available: %v, volumes: %d", bitlocker.Available, len(bitlocker.Volumes))
		for _, v := range bitlocker.Volumes {
			t.Logf("  %+v", v)
		}
	case map[string]string:
		t.Logf("BitLocker error (expected without admin rights): %s", bitlocker["error"])
	default:
		t.Errorf("unexpected bitlocker result: %#v", result["bitlocker"])
	}
	if _, ok := result["firewall"]; !ok {
		t.Error("expected the firewall part")
	}
}
