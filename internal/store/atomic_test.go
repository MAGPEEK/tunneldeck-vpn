package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileAtomicReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	for _, content := range []string{"first", "second, longer content", "3"} {
		if err := writeFileAtomic(osFileSystem{}, path, []byte(content)); err != nil {
			t.Fatalf("write %q: %v", content, err)
		}
		if got := string(readFile(t, dir, "data.json")); got != content {
			t.Fatalf("content = %q, want %q", got, content)
		}
	}
	assertNoTempFiles(t, dir)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("mode = %o, want 600", mode)
		}
	}
}

func TestWriteFileAtomicFailureKeepsOldFile(t *testing.T) {
	for _, step := range []string{"create", "write", "sync", "close", "rename"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "data.json")
			writeFile(t, dir, "data.json", "old")

			err := writeFileAtomic(&faultyFS{failStep: step}, path, []byte("new"))
			if !errors.Is(err, errInjected) {
				t.Fatalf("err = %v, want injected failure", err)
			}
			if got := string(readFile(t, dir, "data.json")); got != "old" {
				t.Fatalf("content = %q, want old content", got)
			}
			assertNoTempFiles(t, dir)
		})
	}
}
