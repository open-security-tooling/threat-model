package mcp

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/open-security-tooling/threat-model/internal/ops"
)

// modelFile is the one file this server reads and writes. Writes are atomic
// (temp file in the same directory, then rename) and detect concurrent
// changes by other programs.
type modelFile struct {
	path string // absolute, symlinks resolved
	mu   sync.Mutex
}

// errChanged means the file changed on disk while an edit was being made.
var errChanged = errors.New("the model file changed on disk while the edit was being made")

func openModelFile(name string) (*modelFile, error) {
	if name == "" {
		return nil, errors.New("no model file given; start the MCP server with --file <path to threatmodel.yaml>")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, fmt.Errorf("can't find the model file %s: %v", name, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("the model file %s doesn't exist; create one with `threat init`", name)
		}
		return nil, fmt.Errorf("can't open the model file %s: %v", name, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("can't open the model file %s: %v", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s isn't a regular file", name)
	}
	return &modelFile{path: resolved}, nil
}

func (f *modelFile) read() ([]byte, error) {
	src, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("couldn't read the model file: %v", err)
	}
	return src, nil
}

// update reads the file, applies fn and, if the source changed, writes the
// result atomically. If another program changed the file between the read and
// the write, it starts over once with the new content, then gives up.
func (f *modelFile) update(fn func(src []byte) (ops.EditResult, error)) (ops.EditResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for attempt := 0; ; attempt++ {
		src, err := f.read()
		if err != nil {
			return ops.EditResult{}, err
		}
		res, err := fn(src)
		if err != nil || !res.Changed {
			return res, err
		}
		err = writeIfUnchanged(f.path, src, []byte(res.Source))
		if errors.Is(err, errChanged) && attempt == 0 {
			continue
		}
		if errors.Is(err, errChanged) {
			return ops.EditResult{}, &ops.Error{Message: "The model file kept changing on disk while the edit was being made, so the edit wasn't saved. Try again once other edits have finished."}
		}
		return res, err
	}
}

// writeIfUnchanged writes data to path unless the file no longer holds want.
func writeIfUnchanged(path string, want, data []byte) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("couldn't read the model file: %v", err)
	}
	if !bytes.Equal(current, want) {
		return errChanged
	}
	return writeAtomic(path, data)
}

// writeAtomic replaces path with data so readers see either the old or the
// new content, never a half-written file. The file mode is preserved.
func writeAtomic(path string, data []byte) (err error) {
	mode := fs.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("couldn't save the model file: %v", err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("couldn't save the model file: %v", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("couldn't save the model file: %v", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("couldn't save the model file: %v", err)
	}
	if err = os.Chmod(tmp.Name(), mode); err != nil {
		return fmt.Errorf("couldn't save the model file: %v", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("couldn't save the model file: %v", err)
	}
	return nil
}

// repoRoot returns the nearest directory at or above dir that contains .git,
// or dir itself (and ok=false) if there is none. It doesn't run git.
func repoRoot(dir string) (root string, ok bool) {
	for d := dir; ; {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d, true
		}
		parent := filepath.Dir(d)
		if parent == d {
			return dir, false
		}
		d = parent
	}
}
