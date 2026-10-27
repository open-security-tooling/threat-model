package serve

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type testServer struct {
	t     *testing.T
	file  string
	base  string // http://127.0.0.1:port
	host  string // 127.0.0.1:port
	token string
}

func startServer(t *testing.T) *testServer {
	t.Helper()
	src, err := os.ReadFile("../../docs/examples/invoice-service.threatmodel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "threatmodel.yaml")
	if err := os.WriteFile(file, src, 0o600); err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{
		"index.html":       {Data: []byte("<!doctype html><title>app</title>")},
		"assets/app.js":    {Data: []byte("console.log(1)")},
		"assets/core.wasm": {Data: []byte("\x00asm\x01\x00\x00\x00")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{File: file, Assets: assets, OnReady: func(u string) { ready <- u }})
	}()
	var link string
	select {
	case link = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server didn't start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v after cancel", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("server didn't shut down")
		}
	})
	u, err := url.Parse(link)
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Fragment, "token=") {
		t.Fatalf("OnReady URL = %q", link)
	}
	token := strings.TrimPrefix(u.Fragment, "token=")
	if b, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(b) != 32 {
		t.Fatalf("token %q isn't 32 random bytes", token)
	}
	return &testServer{t: t, file: file, base: "http://" + u.Host, host: u.Host, token: token}
}

func (s *testServer) do(method, path, body string, mod func(*http.Request)) (*http.Response, map[string]any) {
	s.t.Helper()
	req, err := http.NewRequest(method, s.base+path, strings.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	if mod != nil {
		mod(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(b, &out)
	return resp, out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAuthRequired(t *testing.T) {
	s := startServer(t)
	for name, mod := range map[string]func(*http.Request){
		"no token":    func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong token": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("A", len(s.token))) },
		"basic auth":  func(r *http.Request) { r.SetBasicAuth("x", s.token) },
		"query token": func(r *http.Request) { r.Header.Del("Authorization"); r.URL.RawQuery = "token=" + s.token },
	} {
		resp, out := s.do("GET", "/api/file", "", mod)
		if resp.StatusCode != http.StatusUnauthorized || out["error"] == nil {
			t.Errorf("%s: status %d, body %v", name, resp.StatusCode, out)
		}
		if resp.Header.Get("Content-Security-Policy") != ContentSecurityPolicy {
			t.Errorf("%s: security headers missing on error response", name)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: CORS header sent", name)
		}
	}
	if resp, _ := s.do("PUT", "/api/file", `{"source":"version: 1"}`, func(r *http.Request) { r.Header.Del("Authorization") }); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated PUT: status %d", resp.StatusCode)
	}
}

func TestBadHostRejected(t *testing.T) {
	s := startServer(t)
	_, port, _ := net.SplitHostPort(s.host)
	for _, host := range []string{"evil.example:" + port, "evil.example", "127.0.0.1:1", "localhost", "0.0.0.0:" + port} {
		resp, _ := s.do("GET", "/api/file", "", func(r *http.Request) { r.Host = host })
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Host %q: status %d", host, resp.StatusCode)
		}
		resp, _ = s.do("GET", "/", "", func(r *http.Request) { r.Host = host })
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Host %q on /: status %d", host, resp.StatusCode)
		}
	}
	if resp, _ := s.do("GET", "/api/file", "", func(r *http.Request) { r.Host = "localhost:" + port }); resp.StatusCode != http.StatusOK {
		t.Errorf("localhost Host refused: %d", resp.StatusCode)
	}
}

func TestBadOriginRejected(t *testing.T) {
	s := startServer(t)
	for _, origin := range []string{"http://evil.example", "null", "https://" + s.host, "http://127.0.0.1:1"} {
		resp, _ := s.do("GET", "/api/file", "", func(r *http.Request) { r.Header.Set("Origin", origin) })
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Origin %q: status %d", origin, resp.StatusCode)
		}
	}
	if resp, _ := s.do("GET", "/api/file", "", func(r *http.Request) { r.Header.Set("Origin", s.base) }); resp.StatusCode != http.StatusOK {
		t.Errorf("own origin refused: %d", resp.StatusCode)
	}
}

func TestGetPutRoundTrip(t *testing.T) {
	s := startServer(t)
	resp, out := s.do("GET", "/api/file", "", nil)
	if resp.StatusCode != http.StatusOK || out["name"] != "threatmodel.yaml" || out["source"] != readFile(t, s.file) {
		t.Fatalf("GET: %d %v", resp.StatusCode, out["name"])
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("API response is cacheable")
	}
	edited := out["source"].(string) + "# saved from the app\n"
	body, _ := json.Marshal(map[string]string{"source": edited})
	resp, out = s.do("PUT", "/api/file", string(body), nil)
	if resp.StatusCode != http.StatusOK || out["source"] != edited {
		t.Fatalf("PUT: %d %v", resp.StatusCode, out["error"])
	}
	if readFile(t, s.file) != edited {
		t.Error("PUT didn't write the file")
	}
	if info, _ := os.Stat(s.file); info.Mode().Perm() != 0o600 {
		t.Errorf("file mode changed to %v", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(filepath.Dir(s.file)); len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}

	// A model with validation errors still parses, so it's saved (the app
	// shows the problems); the response says what they are.
	invalid := strings.Replace(edited, "to: api", "to: nowhere", 1)
	body, _ = json.Marshal(map[string]string{"source": invalid})
	resp, out = s.do("PUT", "/api/file", string(body), nil)
	if resp.StatusCode != http.StatusOK || out["validation"].(map[string]any)["ok"] != false {
		t.Errorf("PUT of model with errors: %d %v", resp.StatusCode, out)
	}
}

func TestPutGarbageRefused(t *testing.T) {
	s := startServer(t)
	before := readFile(t, s.file)
	for name, body := range map[string]string{
		"not yaml":       `{"source": "version: [1\nsystem: {"}`,
		"not a model":    `{"source": "- just\n- a list\n"}`,
		"alias bomb":     `{"source": "a: &a [x]\nb: *a\n"}`,
		"no source":      `{"text": "version: 1"}`,
		"not json":       `version: 1`,
		"too big":        `{"source": "` + strings.Repeat("a", maxSource+1) + `"}`,
		"too big escape": `{"source": "` + strings.Repeat(`\n`, int(maxBody)) + `"}`,
	} {
		resp, out := s.do("PUT", "/api/file", body, nil)
		if resp.StatusCode < 400 || out["error"] == nil {
			t.Errorf("%s: status %d, body %v", name, resp.StatusCode, out)
		}
		if name == "not yaml" {
			if e := out["error"].(map[string]any); e["diagnostics"] == nil {
				t.Errorf("no diagnostics for unparseable model: %v", e)
			}
		}
	}
	if readFile(t, s.file) != before {
		t.Error("a refused PUT changed the file")
	}
}

func TestSecurityHeadersAndAssets(t *testing.T) {
	s := startServer(t)
	resp, _ := s.do("GET", "/", "", func(r *http.Request) { r.Header.Del("Authorization") })
	want := map[string]string{
		"Content-Security-Policy":      ContentSecurityPolicy,
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("GET /: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	resp, _ = s.do("GET", "/assets/core.wasm", "", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/wasm" {
		t.Errorf("wasm: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	resp, _ = s.do("GET", "/assets/", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("directory listing served: %d", resp.StatusCode)
	}
	resp, _ = s.do("POST", "/", "", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /: %d", resp.StatusCode)
	}
}

func TestNonLoopbackRefused(t *testing.T) {
	file := filepath.Join(t.TempDir(), "m.yaml")
	os.WriteFile(file, []byte("version: 1\nsystem:\n  name: x\n"), 0o600)
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.168.1.10:8080", "[::]:0", "example.com:80", "127.0.0.1"} {
		err := Run(context.Background(), Options{File: file, Addr: addr})
		if err == nil {
			t.Errorf("%q accepted", addr)
		}
	}
	err := Run(context.Background(), Options{File: file, Addr: "0.0.0.0:0"})
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("error doesn't explain: %v", err)
	}
}

// --- WebSocket ---

type wsClientConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func (s *testServer) dialWatch(t *testing.T, query string, header map[string]string) (*wsClientConn, int) {
	t.Helper()
	conn, err := net.Dial("tcp", s.host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	key := make([]byte, 16)
	rand.Read(key)
	req := "GET /api/watch?" + query + " HTTP/1.1\r\nHost: " + s.host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n"
	for k, v := range header {
		req += k + ": " + v + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		return nil, resp.StatusCode
	}
	return &wsClientConn{conn: conn, r: r}, resp.StatusCode
}

func (c *wsClientConn) readText(t *testing.T, timeout time.Duration) string {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	var hdr [2]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		t.Fatalf("reading frame: %v", err)
	}
	if hdr[0] != 0x81 || hdr[1]&0x80 != 0 {
		t.Fatalf("frame header %x, want an unmasked final text frame", hdr)
	}
	n := uint64(hdr[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		io.ReadFull(c.r, ext[:])
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		io.ReadFull(c.r, ext[:])
		n = binary.BigEndian.Uint64(ext[:])
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

// writeFrame sends a masked frame, as a browser would.
func (c *wsClientConn) writeFrame(op byte, payload []byte) {
	frame := []byte{0x80 | op, 0x80 | byte(len(payload)), 1, 2, 3, 4}
	for i, b := range payload {
		frame = append(frame, b^frame[2+i%4])
	}
	c.conn.Write(frame)
}

func TestWatchPushesChanges(t *testing.T) {
	s := startServer(t)
	c, status := s.dialWatch(t, "token="+s.token, map[string]string{"Origin": s.base})
	if c == nil {
		t.Fatalf("watch handshake: status %d", status)
	}
	var msg map[string]string
	json.Unmarshal([]byte(c.readText(t, 2*time.Second)), &msg)
	if msg["source"] != readFile(t, s.file) {
		t.Fatalf("first message isn't the current file: %v", msg)
	}

	// Ping is answered with a pong carrying the same payload.
	c.writeFrame(0x9, []byte("hi"))
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	pong := make([]byte, 4)
	if _, err := io.ReadFull(c.r, pong); err != nil || pong[0] != 0x8A || string(pong[2:]) != "hi" {
		t.Fatalf("pong = %x, %v", pong, err)
	}

	edited := readFile(t, s.file) + "# edited in another editor\n"
	if err := os.WriteFile(s.file, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(c.readText(t, 3*time.Second)), &msg)
	if msg["source"] != edited {
		t.Fatalf("pushed source isn't the edited file")
	}

	// Close is answered and the connection ends.
	c.writeFrame(0x8, []byte{0x03, 0xE8})
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	closeFrame := make([]byte, 2)
	if _, err := io.ReadFull(c.r, closeFrame); err != nil || closeFrame[0] != 0x88 {
		t.Fatalf("close reply = %x, %v", closeFrame, err)
	}
}

func TestWatchChecks(t *testing.T) {
	s := startServer(t)
	if _, status := s.dialWatch(t, "", nil); status != http.StatusUnauthorized {
		t.Errorf("no token: %d", status)
	}
	if _, status := s.dialWatch(t, "token=wrong", nil); status != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", status)
	}
	if _, status := s.dialWatch(t, "token="+s.token, map[string]string{"Origin": "http://evil.example"}); status != http.StatusForbidden {
		t.Errorf("bad origin: %d", status)
	}
}

func TestPutRefusesStaleRevision(t *testing.T) {
	s := startServer(t)
	_, out := s.do("GET", "/api/file", "", nil)
	rev, _ := out["revision"].(string)
	if rev == "" {
		t.Fatal("GET returned no revision")
	}
	original := out["source"].(string)

	// Someone else (an agent, an editor) changes the file on disk.
	onDisk := original + "# changed by an agent\n"
	if err := os.WriteFile(s.file, []byte(onDisk), 0o600); err != nil {
		t.Fatal(err)
	}

	// The app saves an edit based on the old revision: refused.
	mine := original + "# changed in the app\n"
	body, _ := json.Marshal(map[string]string{"source": mine, "base_revision": rev})
	resp, out := s.do("PUT", "/api/file", string(body), nil)
	if resp.StatusCode != http.StatusConflict || out["source"] != onDisk {
		t.Fatalf("stale PUT: %d %v", resp.StatusCode, out)
	}
	if readFile(t, s.file) != onDisk {
		t.Fatal("stale PUT overwrote the disk change")
	}

	// Based on the latest revision, it's accepted and returns the new one.
	body, _ = json.Marshal(map[string]string{"source": mine, "base_revision": out["revision"].(string)})
	resp, out = s.do("PUT", "/api/file", string(body), nil)
	if resp.StatusCode != http.StatusOK || readFile(t, s.file) != mine || out["revision"] == "" {
		t.Fatalf("fresh PUT: %d %v", resp.StatusCode, out)
	}
}
