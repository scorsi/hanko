// Package state confines private files to checked, open directory handles (ADR 0005).
package state

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Open rejects a symlink at the state boundary. System-owned ancestors such as /var may be links.
func Open(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("state directory must be a clean absolute path")
	}
	p, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer p.Close()
	return Directory(p, filepath.Base(path), os.Getegid(), false)
}

// Directory checks the opened inode as well as its name, so replacing the pathname cannot
// redirect subsequent reads or writes. Consumer groups need not be groups hanko belongs to.
func Directory(parent *os.Root, name string, gid int, certificate bool) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if !before.IsDir() {
		return nil, fmt.Errorf("directory %s: must be a directory, not a symlink", name)
	}
	d, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	after, err := d.Stat(".")
	if err == nil && !os.SameFile(before, after) {
		err = errors.New("directory changed while opening it")
	}
	if err == nil {
		err = checkDirectory(after, gid, certificate)
	}
	if err != nil {
		d.Close()
		return nil, fmt.Errorf("directory %s: %w", name, err)
	}
	return d, nil
}

func checkDirectory(info os.FileInfo, gid int, certificate bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || int(st.Gid) != gid {
		return errors.New("unexpected directory owner or group")
	}
	if info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o700 != 0o700 {
		return errors.New("directory must be writable by its owner only")
	}
	if certificate && info.Mode() != os.ModeDir|os.ModeSetgid|0o750 {
		return errors.New("certificate directory must have mode 2750 (setgid)")
	}
	return nil
}

// OpenFile never follows a symlink or waits on a FIFO. Metadata is checked before reading.
func OpenFile(dir *os.Root, name string, flags int, mode os.FileMode, gid int) (*os.File, error) {
	before, err := dir.Lstat(name)
	switch {
	case errors.Is(err, os.ErrNotExist) && flags&os.O_CREATE != 0:
		flags |= os.O_EXCL
	case err != nil:
		return nil, err
	case !before.Mode().IsRegular():
		return nil, fmt.Errorf("%s: must be a regular file, not a symlink", name)
	}
	f, err := dir.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if before == nil && errors.Is(err, os.ErrExist) {
		// Another run created the lock first; check that inode rather than following it blindly.
		return OpenFile(dir, name, flags&^(os.O_CREATE|os.O_EXCL), mode, gid)
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && before != nil && !os.SameFile(before, info) {
		err = fmt.Errorf("%s: file changed while opening it", name)
	}
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || int(st.Uid) != os.Geteuid() || int(st.Gid) != gid ||
			info.Mode().Perm()&^mode != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || st.Nlink != 1 {
			err = fmt.Errorf("%s: unexpected file type, owner, group, links or permissions (maximum %04o)", name, mode)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ReadOptional returns nil for an absent file, but rejects unsafe existing files.
func ReadOptional(dir *os.Root, name string, mode os.FileMode, gid int) ([]byte, error) {
	f, err := OpenFile(dir, name, os.O_RDONLY, mode, gid)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

type File struct {
	Name string
	Data []byte
}

// WriteFiles stages and syncs every file before renaming any; the directory is synced last.
// Two renames are not atomic together: callers must check certificate/key pairs on every run.
func WriteFiles(dir *os.Root, mode os.FileMode, files ...File) error {
	var tmps []string
	defer func() {
		for _, name := range tmps {
			dir.Remove(name)
		}
	}()
	for _, file := range files {
		if filepath.Base(file.Name) != file.Name || file.Name == "." || file.Name == ".." {
			return errors.New("invalid state file name")
		}
		name := "." + file.Name + "." + rand.Text()
		f, err := dir.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		tmps = append(tmps, name)
		_, err = f.Write(file.Data)
		if err == nil {
			err = f.Chmod(mode)
		}
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	for n, file := range files {
		if err := dir.Rename(tmps[n], file.Name); err != nil {
			return err
		}
	}
	return Sync(dir)
}

func Sync(dir *os.Root) error {
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
