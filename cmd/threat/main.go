// Command threat is the CLI for threat-model: validate, format, explain and
// check threat models, and run the MCP server and local web app.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/open-security-tooling/threat-model/internal/risk"
)

var version = "" // set by release builds: -ldflags "-X main.version=..."

// currentVersion reports the release version, or the module version for
// `go install ...@v0.1.0` builds, which don't get -X main.version.
func currentVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(info.Main.Version, "v") {
		return info.Main.Version[1:]
	}
	return "dev"
}

// Exit codes: 0 ok, 1 findings, 2 usage or parse error.
const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

type command struct {
	name    string
	summary string
	run     func(args []string) int
}

var commands []command

func init() {
	commands = []command{
		{"init", "Create a starter threatmodel.yaml", cmdInit},
		{"validate", "Check the model for mistakes", cmdValidate},
		{"lint", "Like validate, plus the writing rules for threats and mitigations", cmdLint},
		{"fmt", "Format the model in canonical style", cmdFmt},
		{"show", "Summarise the model", cmdShow},
		{"explain", "Explain a threat or mitigation in plain language", cmdExplain},
		{"status", "Change a threat's or mitigation's status", cmdStatus},
		{"check", "Everything CI cares about", cmdCheck},
		{"report", "Write a Markdown report", cmdReport},
		{"suggest", "Suggest threats from the library", cmdSuggest},
		{"paths", "Find attack paths and blast radius", cmdPaths},
		{"serve", "Open the web app on this machine with live reload", cmdServe},
		{"mcp", "Run the MCP server for agents (stdio)", cmdMCP},
		{"schema", "Print the JSON Schema for the file format", cmdSchema},
		{"version", "Print the version", func([]string) int { fmt.Println("threat", currentVersion()); return exitOK }},
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(os.Stdout)
		return exitOK
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(args[1:])
		}
	}
	fmt.Fprintf(os.Stderr, "threat: unknown command %q\n\n", args[0])
	usage(os.Stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "threat: threat models for developers, kept in your repo.\n\nUsage: threat <command> [flags]\n\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nRun `threat <command> -h` for a command's flags. Most commands take --json.")
}

// flags is the common flag set: --file and --json.
type flags struct {
	*flag.FlagSet
	file string
	json bool
	pos  []string
}

func newFlags(name, usage string) *flags {
	f := &flags{FlagSet: flag.NewFlagSet(name, flag.ContinueOnError)}
	f.StringVar(&f.file, "file", "", "model file (default: threatmodel.yaml here or in a parent directory)")
	f.StringVar(&f.file, "f", "", "shorthand for --file")
	f.BoolVar(&f.json, "json", false, "print JSON for scripts and agents")
	f.Usage = func() {
		fmt.Fprintf(f.Output(), "Usage: threat %s\n\nFlags:\n", usage)
		f.PrintDefaults()
	}
	return f
}

// parse accepts flags before, between and after positional arguments, so
// `threat explain some-id --json` works.
func (f *flags) parse(args []string) bool {
	for {
		if err := f.Parse(args); err != nil {
			return false
		}
		rest := f.FlagSet.Args()
		if len(rest) == 0 {
			return true
		}
		f.pos = append(f.pos, rest[0])
		args = rest[1:]
	}
}

func (f *flags) NArg() int        { return len(f.pos) }
func (f *flags) Arg(i int) string { return f.pos[i] }

const defaultFile = "threatmodel.yaml"

// modelPath finds the model file: --file, else threatmodel.yaml in the
// current directory or the nearest parent, stopping at the repository root.
func (f *flags) modelPath() (string, error) {
	if f.file != "" {
		return f.file, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, defaultFile)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("no threatmodel.yaml found here or in a parent directory. Run `threat init` to create one, or pass --file")
}

func (f *flags) read() (path string, src []byte, ok bool) {
	path, err := f.modelPath()
	if err == nil {
		src, err = os.ReadFile(path)
	}
	if err != nil {
		fail(err)
		return "", nil, false
	}
	return path, src, true
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "threat:", err)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeAtomic replaces path's content without leaving a half-written file.
func writeAtomic(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".threatmodel-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Terminal styling, off when not a terminal or NO_COLOR is set.

var color = func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}()

func style(code, s string) string {
	if !color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string { return style("1", s) }
func dim(s string) string  { return style("2", s) }

var levelStyle = map[string]string{"critical": "1;37;41", "high": "1;31", "medium": "1;33", "low": "1;32"}

func level(l string) string {
	if l == "" {
		return dim("UNASSESSED")
	}
	return style(levelStyle[l], strings.ToUpper(l))
}

// riskLabel is the label for a threat's current risk: its level, N/A for
// threats that don't apply, or UNASSESSED.
func riskLabel(a risk.Assessment) string {
	if a.NotApplicable {
		return dim("N/A")
	}
	if !a.Assessed {
		return level("")
	}
	return level(a.Level)
}

// visibleWidth is the width of s on a terminal, ignoring ANSI styling.
func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j + 1
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

// pad right-pads s with spaces to the visible width w.
func pad(s string, w int) string {
	if n := visibleWidth(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// widest is the visible width of the widest label.
func widest(labels ...string) int {
	w := 0
	for _, l := range labels {
		w = max(w, visibleWidth(l))
	}
	return w
}

func sev(s string) string {
	if s == "error" {
		return style("1;31", "✗")
	}
	return style("1;33", "!")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
