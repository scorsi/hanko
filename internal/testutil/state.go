// Package testutil provides shared test fixtures.
package testutil

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// StateDir creates a temporary state directory owned by the test process.
func StateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// BSD inherits the parent's group, which may differ from the process's group.
	if err := os.Chown(dir, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	return dir
}

// SetgidDir gives dir mode 2750, as the module provisions certificate directories (ADR 0005),
// and skips the test where the environment forbids it: the Nix build sandbox's seccomp filter
// refuses setgid modes with EPERM, and some macOS filesystems silently drop the bit.
// The NixOS VM test checks the same directories as a real system.
func SetgidDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, os.ModeSetgid|0o750); errors.Is(err, syscall.EPERM) {
		t.Skipf("environment refuses setgid directories (%v); covered by the NixOS VM test", err)
	} else if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if info.Mode()&os.ModeSetgid == 0 {
		t.Skip("filesystem drops setgid; covered by the NixOS VM test")
	}
}
