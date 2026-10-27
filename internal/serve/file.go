package serve

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// resolveFile returns the absolute, symlink-resolved path of the model file,
// which must exist.
func resolveFile(name string) (string, error) {
	if name == "" {
		return "", errors.New("no model file given; run `threat serve <path to threatmodel.yaml>`")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("can't find the model file %s: %v", name, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("the model file %s doesn't exist; create one with `threat init`", name)
		}
		return "", fmt.Errorf("can't open the model file %s: %v", name, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("can't open the model file %s: %v", name, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s isn't a regular file", name)
	}
	return resolved, nil
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

// fileState identifies a version of the file on disk.
type fileState struct {
	modTime time.Time
	size    int64
	hash    [sha256.Size]byte
}

// pollInterval is how often the watcher looks at the file.
var pollInterval = 300 * time.Millisecond

// watcher polls a file and reports when its content changes. It reads and
// hashes the file only when its modification time or size changed.
type watcher struct {
	path string
	last fileState
}

// newWatcher starts from initial, the content the caller already has, so a
// change made right after that read is still reported.
func newWatcher(path string, initial []byte) *watcher {
	w := &watcher{path: path, last: fileState{hash: sha256.Sum256(initial)}}
	return w
}

// run calls onChange with the new content whenever it differs from the last
// content seen, until stop is closed.
func (w *watcher) run(stop <-chan struct{}, onChange func(src []byte)) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if src, ok := w.poll(); ok {
			onChange(src)
		}
	}
}

func (w *watcher) poll() ([]byte, bool) {
	info, err := os.Stat(w.path)
	if err != nil {
		return nil, false // e.g. an editor replacing the file; try again next tick
	}
	if info.ModTime().Equal(w.last.modTime) && info.Size() == w.last.size {
		return nil, false
	}
	src, err := os.ReadFile(w.path)
	if err != nil {
		return nil, false
	}
	h := sha256.Sum256(src)
	changed := h != w.last.hash
	w.last = fileState{info.ModTime(), info.Size(), h}
	return src, changed
}
