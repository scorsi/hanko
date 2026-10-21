// Package testutil provides shared test fixtures.
package testutil

import (
	"os"
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
