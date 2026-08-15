package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func ValidateDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat evidence directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("evidence path %s is not a directory", path)
	}
	return nil
}

func CheckWritable(path string) error {
	if err := ValidateDirectory(path); err != nil {
		return err
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate write probe name: %w", err)
	}
	probe := filepath.Join(path, ".notaihoney-write-probe-"+hex.EncodeToString(nonce[:]))
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("open write probe in %s: %w", path, err)
	}
	closeErr := f.Close()
	removeErr := os.Remove(probe)
	if closeErr != nil {
		return fmt.Errorf("close write probe in %s: %w", path, closeErr)
	}
	if removeErr != nil {
		return fmt.Errorf("remove write probe in %s: %w", path, removeErr)
	}
	return nil
}

func FreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func RequireFreeBytes(path string, minimum uint64) (uint64, error) {
	available, err := FreeBytes(path)
	if err != nil {
		return 0, err
	}
	if available <= minimum {
		return available, fmt.Errorf("EVIDENCE_STORAGE_LOW path=%s available_bytes=%d minimum_bytes=%d", path, available, minimum)
	}
	return available, nil
}
