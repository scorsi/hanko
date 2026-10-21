package state

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/scorsi/hanko/internal/testutil"
)

type metadata struct {
	mode os.FileMode
	st   syscall.Stat_t
}

func (m metadata) Name() string       { return "test" }
func (m metadata) Size() int64        { return 0 }
func (m metadata) Mode() os.FileMode  { return m.mode }
func (m metadata) ModTime() time.Time { return time.Time{} }
func (m metadata) IsDir() bool        { return m.mode.IsDir() }
func (m metadata) Sys() any           { return &m.st }

func TestDirectoryPermissions(t *testing.T) {
	good := metadata{os.ModeDir | os.ModeSetgid | 0o750, syscall.Stat_t{Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())}}
	if err := checkDirectory(good, os.Getegid(), true); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"owner", "group", "setgid", "writable", "world readable"} {
		t.Run(kind, func(t *testing.T) {
			bad := good
			switch kind {
			case "owner":
				bad.st.Uid++
			case "group":
				bad.st.Gid++
			case "setgid":
				bad.mode &^= os.ModeSetgid
			case "writable":
				bad.mode |= 0o020
			case "world readable":
				bad.mode |= 0o004
			}
			if err := checkDirectory(bad, os.Getegid(), true); err == nil {
				t.Fatal("unsafe directory accepted")
			}
		})
	}
}

func TestStateBoundaries(t *testing.T) {
	path := testutil.StateDir(t)
	root, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	outside := filepath.Join(t.TempDir(), "key")
	os.WriteFile(outside, []byte("untouched"), 0o600)
	for _, name := range []string{"account.key", "key.pem", ".lock", ".retry-after"} {
		t.Run(name, func(t *testing.T) {
			if err := root.Symlink(outside, name); err != nil {
				t.Fatal(err)
			}
			if f, err := OpenFile(root, name, os.O_CREATE|os.O_RDWR, 0o600, os.Getegid()); err == nil {
				f.Close()
				t.Fatal("followed symlink")
			}
			if got, _ := os.ReadFile(outside); string(got) != "untouched" {
				t.Fatal("changed symlink target")
			}
		})
	}
	root.WriteFile("private", []byte("key"), 0o600)
	root.Symlink("private", "relative-link")
	if f, err := OpenFile(root, "relative-link", os.O_RDONLY, 0o600, os.Getegid()); err == nil {
		f.Close()
		t.Fatal("followed relative symlink")
	}
	if err := root.Symlink(t.TempDir(), "home"); err != nil {
		t.Fatal(err)
	}
	if d, err := Directory(root, "home", os.Getegid(), true); err == nil {
		d.Close()
		t.Fatal("followed directory symlink")
	}
	link := filepath.Join(t.TempDir(), "state")
	os.Symlink(path, link)
	if d, err := Open(link); err == nil {
		d.Close()
		t.Fatal("followed state symlink")
	}
}

func TestOpenFileRejectsUnsafeMetadata(t *testing.T) {
	root, err := Open(testutil.StateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, kind := range []string{"permissions", "directory", "fifo", "hardlink", "group"} {
		t.Run(kind, func(t *testing.T) {
			name := kind
			switch kind {
			case "directory":
				root.Mkdir(name, 0o700)
			case "fifo":
				if err := syscall.Mkfifo(filepath.Join(root.Name(), name), 0o600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				root.WriteFile("source", nil, 0o600)
				root.Link("source", name)
			default:
				root.WriteFile(name, nil, 0o600)
			}
			gid := os.Getegid()
			if kind == "group" {
				gid++
			}
			if kind == "permissions" {
				root.Chmod(name, 0o644)
			}
			if f, err := OpenFile(root, name, os.O_RDONLY, 0o600, gid); err == nil {
				f.Close()
				t.Fatal("unsafe file accepted")
			}
		})
	}
}

func TestWritesStayInOpenedDirectory(t *testing.T) {
	parent := testutil.StateDir(t)
	path := filepath.Join(parent, "state")
	os.Mkdir(path, 0o700)
	root, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	os.Rename(path, filepath.Join(parent, "original"))
	outside := t.TempDir()
	os.Symlink(outside, path)
	if err := WriteFiles(root, 0o600, File{"key", []byte("private")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "key")); !os.IsNotExist(err) {
		t.Fatalf("write escaped: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(parent, "original", "key")); string(got) != "private" {
		t.Fatal("lost rooted write")
	}
}

func TestConcurrentLockCreation(t *testing.T) {
	root, err := Open(testutil.StateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	start := make(chan struct{})
	results := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			f, err := OpenFile(root, ".lock", os.O_CREATE|os.O_RDWR, 0o600, os.Getegid())
			if err == nil {
				err = f.Close()
			}
			results <- err
		}()
	}
	close(start)
	for range 8 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}
