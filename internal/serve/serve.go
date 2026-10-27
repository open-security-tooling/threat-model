// Package serve is the local server behind `threat serve`: it serves the web
// app, lets it read and save one model file, and pushes changes to the file
// over a WebSocket so the app updates live when an editor or agent edits it.
//
// It is built to be safe to leave running while you browse:
//
//   - it listens on 127.0.0.1 only, on a random port by default;
//   - every API request and WebSocket needs a per-run random token;
//   - requests for any Host other than 127.0.0.1:<port> or localhost:<port>
//     are refused (DNS rebinding), and so are API requests from any other
//     Origin; there are no CORS headers;
//   - it only ever writes the file it was started with, and only content
//     that parses as a model.
package serve

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
)

// Options configure the server.
type Options struct {
	// File is the model file to serve. It is the only file ever written.
	File string
	// Addr is where to listen; it must be on 127.0.0.1 (or localhost).
	// Default 127.0.0.1:0, a random free port.
	Addr string
	// Assets is the built web app, served at /. May be nil.
	Assets fs.FS
	// OnReady, if set, is called once the server is listening, with the URL
	// to open: http://127.0.0.1:<port>/#token=<token>.
	OnReady func(url string)
}

// ContentSecurityPolicy is sent with every response.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws://127.0.0.1:*; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// maxSource is the largest model the server accepts, the parser's own limit.
var maxSource = model.DefaultLimits.MaxBytes

// maxBody leaves room for JSON escaping of a model of maxSource bytes.
var maxBody = int64(2*maxSource + 64<<10)

type server struct {
	path   string // resolved model path
	name   string // basename shown in the app
	token  string
	port   string
	assets fs.FS
	files  http.Handler

	writeMu sync.Mutex

	mu      sync.Mutex
	latest  []byte // the file content last seen by the watcher
	clients map[*wsClient]struct{}
}

type wsClient struct {
	c    *wsConn
	send chan []byte // holds at most the newest message
}

// push queues m, replacing any message not yet sent: only the newest
// content matters.
func (cl *wsClient) push(m []byte) {
	for {
		select {
		case cl.send <- m:
			return
		default:
		}
		select {
		case <-cl.send:
		default:
		}
	}
}

// Run serves until ctx is cancelled, then shuts down and returns nil. It
// returns an error if the options are invalid or the server can't start.
func Run(ctx context.Context, opts Options) error {
	file, err := resolveFile(opts.File)
	if err != nil {
		return err
	}
	addr, err := loopbackAddr(opts.Addr)
	if err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	initial, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("couldn't read the model file: %v", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("couldn't listen on %s: %v", addr, err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	s := &server{
		path:    file,
		name:    filepath.Base(opts.File),
		token:   token,
		port:    port,
		assets:  opts.Assets,
		latest:  initial,
		clients: map[*wsClient]struct{}{},
	}
	if opts.Assets != nil {
		s.files = http.FileServerFS(opts.Assets)
	}
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	stop := make(chan struct{})
	w := newWatcher(file, initial)
	go w.run(stop, s.changed)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	if opts.OnReady != nil {
		opts.OnReady("http://127.0.0.1:" + port + "/#token=" + token)
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		close(stop)
		s.closeClients()
		return fmt.Errorf("the server stopped unexpectedly: %v", err)
	}
	close(stop)
	s.closeClients()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		srv.Close()
	}
	return nil
}

// loopbackAddr checks that addr is on 127.0.0.1 and returns it in the form
// to listen on.
func loopbackAddr(addr string) (string, error) {
	if addr == "" {
		return "127.0.0.1:0", nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("%q isn't an address like 127.0.0.1:8080", addr)
	}
	if host != "127.0.0.1" && !strings.EqualFold(host, "localhost") {
		return "", fmt.Errorf("threat serve only listens on 127.0.0.1, so other machines can't reach your threat model; %q isn't allowed", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("%q isn't a valid port", port)
	}
	return net.JoinHostPort("127.0.0.1", port), nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("couldn't generate an access token: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// --- routing and checks ---

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if !s.hostOK(r.Host) {
		writeError(w, http.StatusForbidden, "This server only answers requests for 127.0.0.1:"+s.port+".")
		return
	}
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		s.api(w, r)
		return
	}
	s.static(w, r)
}

// hostOK blocks DNS rebinding: a page on evil.example that resolves to
// 127.0.0.1 still sends Host: evil.example.
func (s *server) hostOK(host string) bool {
	return host == "127.0.0.1:"+s.port || strings.EqualFold(host, "localhost:"+s.port)
}

func (s *server) originOK(r *http.Request) bool {
	origin, ok := r.Header["Origin"]
	if !ok {
		return true
	}
	return len(origin) == 1 && strings.EqualFold(origin[0], "http://"+r.Host)
}

func (s *server) tokenOK(t string) bool {
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *server) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.originOK(r) {
		writeError(w, http.StatusForbidden, "Requests from other websites aren't allowed.")
		return
	}
	if r.URL.Path == "/api/watch" {
		t := r.URL.Query().Get("token")
		if t == "" {
			t = bearer(r)
		}
		if !s.tokenOK(t) {
			writeError(w, http.StatusUnauthorized, "The access token is missing or wrong. Open the link `threat serve` printed.")
			return
		}
		s.watch(w, r)
		return
	}
	if !s.tokenOK(bearer(r)) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "The access token is missing or wrong. Open the link `threat serve` printed.")
		return
	}
	if r.URL.Path != "/api/file" {
		writeError(w, http.StatusNotFound, "There's no API endpoint "+r.URL.Path+".")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getFile(w)
	case http.MethodPut:
		s.putFile(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeError(w, http.StatusMethodNotAllowed, "Use GET to read the file and PUT to save it.")
	}
}

// --- API ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":{"message":"internal error"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(b)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": &ops.Error{Message: msg}})
}

func (s *server) getFile(w http.ResponseWriter) {
	src, err := os.ReadFile(s.path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't read the model file: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"source": string(src), "name": s.name, "revision": revision(src)})
}

func (s *server) putFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var body struct {
		Source *string `json:"source"`
		// BaseRevision, if sent, is the revision the edit was based on.
		// If the file has changed on disk since, the write is refused so
		// it can't silently overwrite someone else's change.
		BaseRevision string `json:"base_revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("The model is too large; the limit is %d MiB.", maxSource>>20))
			return
		}
		writeError(w, http.StatusBadRequest, "Send the file as JSON: {\"source\": \"...\"}.")
		return
	}
	if body.Source == nil {
		writeError(w, http.StatusBadRequest, "Send the file as JSON: {\"source\": \"...\"}.")
		return
	}
	src := []byte(*body.Source)
	if len(src) > maxSource {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("The model is too large; the limit is %d MiB.", maxSource>>20))
		return
	}
	if l := ops.Load(src); l.Model == nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": &ops.Error{
			Message:     "That can't be read as a threat model, so it wasn't saved. Fix these problems first.",
			Diagnostics: l.Diagnostics,
		}})
		return
	}
	validation := ops.Validate(src)

	s.writeMu.Lock()
	current, err := os.ReadFile(s.path)
	if err == nil && body.BaseRevision != "" && body.BaseRevision != revision(current) && !bytes.Equal(current, src) {
		s.writeMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":    &ops.Error{Message: "The file changed on disk while you were editing, so your change wasn't saved. The latest version is loaded; make the change again."},
			"source":   string(current),
			"revision": revision(current),
		})
		return
	}
	if err != nil || !bytes.Equal(current, src) {
		err = writeAtomic(s.path, src)
	}
	s.writeMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, capitalize(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": string(src), "revision": revision(src), "validation": validation})
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// --- live updates ---

func sourceMessage(src []byte) []byte {
	b, _ := json.Marshal(map[string]string{"source": string(src), "revision": revision(src)})
	return b
}

// revision identifies a version of the file's content.
func revision(src []byte) string {
	sum := sha256.Sum256(src)
	return hex.EncodeToString(sum[:16])
}

// changed is called by the watcher with new file content.
func (s *server) changed(src []byte) {
	m := sourceMessage(src)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest = src
	for cl := range s.clients {
		cl.push(m)
	}
}

// watch upgrades to a WebSocket that first sends the current content, then
// every new version of the file.
func (s *server) watch(w http.ResponseWriter, r *http.Request) {
	c, err := upgrade(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, capitalize(err.Error()))
		return
	}
	cl := &wsClient{c: c, send: make(chan []byte, 1)}
	s.mu.Lock()
	s.clients[cl] = struct{}{}
	cl.push(sourceMessage(s.latest))
	s.mu.Unlock()

	go c.readLoop()
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.clients, cl)
			s.mu.Unlock()
		}()
		for {
			select {
			case m := <-cl.send:
				if err := c.sendText(m); err != nil {
					c.close(1011, "")
					return
				}
			case <-c.done:
				return
			}
		}
	}()
}

func (s *server) closeClients() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for cl := range s.clients {
		cl.c.close(1001, "threat serve is shutting down")
	}
}

// --- static files ---

var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".wasm":        "application/wasm",
	".woff2":       "font/woff2",
	".txt":         "text/plain; charset=utf-8",
}

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "Only GET and HEAD are allowed here.")
		return
	}
	if s.files == nil {
		http.Error(w, "This build of threat has no web app bundled.", http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" {
		name = "."
	}
	if info, err := fs.Stat(s.assets, name); err == nil && info.IsDir() {
		// No directory listings: only directories with an index page.
		if _, err := fs.Stat(s.assets, path.Join(name, "index.html")); err != nil {
			http.NotFound(w, r)
			return
		}
		name = path.Join(name, "index.html")
	}
	// Set types explicitly rather than trusting the OS's MIME table; with
	// nosniff, a wrong type stops scripts and WebAssembly from loading.
	if ct, ok := contentTypes[path.Ext(name)]; ok {
		w.Header().Set("Content-Type", ct)
	}
	s.files.ServeHTTP(w, r)
}
