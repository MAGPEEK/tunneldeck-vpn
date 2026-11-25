package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// fileSystem is the seam between the store and the disk, so tests can inject
// failures into each step of an atomic write.
type fileSystem interface {
	ReadFile(name string) ([]byte, error)
	MkdirAll(path string, perm os.FileMode) error
	CreateTemp(dir, pattern string) (tempFile, error)
	Rename(oldPath, newPath string) error
	Remove(name string) error
}

// tempFile is the part of *os.File used by writeFileAtomic.
type tempFile interface {
	Name() string
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// osFileSystem is the real file system.
type osFileSystem struct{}

func (osFileSystem) ReadFile(name string) ([]byte, error)         { return os.ReadFile(name) }
func (osFileSystem) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (osFileSystem) Rename(oldPath, newPath string) error         { return os.Rename(oldPath, newPath) }
func (osFileSystem) Remove(name string) error                     { return os.Remove(name) }

// CreateTemp creates the file with mode 0600, as os.CreateTemp guarantees.
func (osFileSystem) CreateTemp(dir, pattern string) (tempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// writeFileAtomic replaces path with data: it writes a temp file in the same
// directory, syncs it, closes it and renames it over path (os.Rename replaces
// an existing file on Unix and Windows). On any failure the temp file is
// removed and path is left untouched.
func writeFileAtomic(fsys fileSystem, path string, data []byte) (err error) {
	tmp, err := fsys.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = fsys.Remove(tmp.Name())
		}
	}()
	if err = writeAndClose(tmp, data); err != nil {
		return err
	}
	if err = fsys.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

func writeAndClose(f tempFile, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return nil
}
