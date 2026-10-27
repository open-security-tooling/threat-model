package check

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"strings"
)

// Git runs the user's git in a repository. Arguments are never built into a
// shell string, refs are validated, and every ref is passed after
// --end-of-options so it can't be read as a flag.
type Git struct {
	Dir string
	// Env is extra environment for git (tests use it to isolate config).
	Env []string
}

var refPattern = regexp.MustCompile(`^[A-Za-z0-9._/@{}~^-]+$`)

func validRef(ref string) error {
	if ref == "" || strings.HasPrefix(ref, "-") || !refPattern.MatchString(ref) || strings.Contains(ref, "..") {
		return fmt.Errorf("%q isn't a git ref this tool accepts; use a branch, tag or commit like origin/main", ref)
	}
	return nil
}

func (g *Git) run(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.Dir
	cmd.Env = append(cmd.Environ(), g.Env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git %s failed: %s", args[0], msg)
	}
	return out, nil
}

// ChangedSince lists files changed between the merge base with ref and the
// working tree, including uncommitted changes.
func (g *Git) ChangedSince(ref string) ([]string, error) {
	if err := validRef(ref); err != nil {
		return nil, err
	}
	out, err := g.run("diff", "--name-only", "--no-renames", "--merge-base", "--end-of-options", ref)
	if err != nil {
		return nil, err
	}
	return lines(out), nil
}

// Show returns a file's content at ref.
func (g *Git) Show(ref, file string) ([]byte, error) {
	if err := validRef(ref); err != nil {
		return nil, err
	}
	return g.run("show", "--end-of-options", ref+":"+path.Clean(file))
}

// LastChange returns the date (YYYY-MM-DD) of the last commit touching any
// of the globs, or "" if none.
func (g *Git) LastChange(globs []string) (string, error) {
	args := []string{"log", "-1", "--format=%cs", "--"}
	for _, gl := range globs {
		args = append(args, ":(glob)"+gl)
	}
	out, err := g.run(args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// matchAny reports whether file matches any of the globs. Globs use path.Match
// syntax per segment, plus ** for any number of directories.
func matchAny(globs []string, file string) bool {
	for _, g := range globs {
		if matchGlob(strings.Split(path.Clean(g), "/"), strings.Split(file, "/")) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, parts []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			rest := pattern[1:]
			for i := 0; i <= len(parts); i++ {
				if matchGlob(rest, parts[i:]) {
					return true
				}
			}
			return false
		}
		if len(parts) == 0 {
			return false
		}
		if ok, err := path.Match(pattern[0], parts[0]); err != nil || !ok {
			return false
		}
		pattern, parts = pattern[1:], parts[1:]
	}
	return len(parts) == 0
}
