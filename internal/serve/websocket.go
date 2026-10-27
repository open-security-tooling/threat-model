package serve

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// A minimal RFC 6455 WebSocket server: the handshake, unfragmented text
// frames from server to client, and close/ping handling for frames from the
// client. That's all live reload needs, and it avoids a dependency.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// maxClientFrame bounds frames from the client. The app never sends data
// over the socket, so anything bigger than a control frame is unexpected.
const maxClientFrame = 4 << 10

const wsWriteTimeout = 10 * time.Second

type wsConn struct {
	conn net.Conn
	rw   *bufio.ReadWriter
	mu   sync.Mutex // serialises writes
	once sync.Once
	done chan struct{}
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// upgrade performs the server side of the opening handshake.
func upgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if r.Method != http.MethodGet {
		return nil, errors.New("the watch endpoint needs a GET request")
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") || !headerHasToken(r.Header, "Upgrade", "websocket") {
		return nil, errors.New("the watch endpoint only speaks WebSocket")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		return nil, errors.New("only WebSocket version 13 is supported")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if b, err := base64.StdEncoding.DecodeString(key); err != nil || len(b) != 16 {
		return nil, errors.New("the WebSocket key is missing or malformed")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("this connection can't be upgraded to a WebSocket")
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])

	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	// The server's read and write timeouts were set on the connection for
	// ordinary requests; a WebSocket lives longer.
	conn.SetDeadline(time.Time{})
	c := &wsConn{conn: conn, rw: rw, done: make(chan struct{})}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	c.mu.Lock()
	defer c.mu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	if _, err := rw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// writeFrame writes one unmasked, unfragmented frame.
func (c *wsConn) writeFrame(op byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hdr [10]byte
	hdr[0] = 0x80 | op // FIN
	n := 2
	switch l := len(payload); {
	case l < 126:
		hdr[1] = byte(l)
	case l <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(l))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
		n = 10
	}
	c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	if _, err := c.rw.Write(hdr[:n]); err != nil {
		return err
	}
	if _, err := c.rw.Write(payload); err != nil {
		return err
	}
	return c.rw.Flush()
}

func (c *wsConn) sendText(b []byte) error { return c.writeFrame(opText, b) }

// close sends a close frame (best effort) and closes the connection.
func (c *wsConn) close(code uint16, reason string) {
	c.once.Do(func() {
		payload := binary.BigEndian.AppendUint16(nil, code)
		payload = append(payload, reason...)
		c.writeFrame(opClose, payload)
		c.conn.Close()
		close(c.done)
	})
}

// readLoop reads frames from the client until the connection ends. It
// answers pings and close frames, and discards everything else.
func (c *wsConn) readLoop() {
	defer c.close(1000, "")
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c.rw, hdr[:]); err != nil {
			return
		}
		op := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		length := uint64(hdr[1] & 0x7F)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.rw, ext[:]); err != nil {
				return
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.rw, ext[:]); err != nil {
				return
			}
			length = binary.BigEndian.Uint64(ext[:])
		}
		if !masked { // RFC 6455 5.1: clients must mask
			c.close(1002, "frames from the client must be masked")
			return
		}
		if op >= opClose && length > 125 {
			c.close(1002, "control frames must be 125 bytes or less")
			return
		}
		if length > maxClientFrame {
			c.close(1009, "message too big")
			return
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.rw, mask[:]); err != nil {
			return
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.rw, payload); err != nil {
			return
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		switch op {
		case opClose:
			c.close(1000, "")
			return
		case opPing:
			if c.writeFrame(opPong, payload) != nil {
				return
			}
		case opPong, opText, opBinary, opContinuation:
			// ignored
		default:
			c.close(1002, "unknown frame type")
			return
		}
	}
}
