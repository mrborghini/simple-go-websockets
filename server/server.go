package server

import (
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"
)

type WSHandler interface {
	OnMessage(WSConn, string)
	OnClose(WSConn)
	OnError(error)
	OnConnect(WSConn)
}

type WSConn struct {
	conn io.ReadWriteCloser
}

func (c *WSConn) Send(message string) error {
	return writeFrame(c.conn, []byte(message))
}

func (c *WSConn) Close() error {
	return c.conn.Close()
}

// WebSocket magic string
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Upgrade HTTP to WebSocket
func UpgradeToWebSocket(w http.ResponseWriter, r *http.Request, handler WSHandler) {
	// Check for WebSocket headers
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "Invalid WebSocket handshake", http.StatusBadRequest)
		return
	}

	// Compute Sec-WebSocket-Accept
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	hash := sha1.Sum([]byte(key + wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(hash[:])

	// Hijack connection
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}

	// Send handshake response
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

	_, err = conn.Write([]byte(response))
	if err != nil {
		conn.Close()
		return
	}

	wsConn := WSConn{conn: conn}
	handler.OnConnect(wsConn) // Notify the handler of the new connection
	go handleWebSocket(conn, handler)
}

func pingLoop(conn io.ReadWriteCloser, done <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			conn.Write([]byte{0x89, 0x00}) // 0x89 = PING frame with 0 payload
		case <-done:
			return
		}
	}
}


func readFrame(conn io.Reader) ([]byte, error) {
	// Read first 2 bytes (FIN, RSV, Opcode | MASK, Payload length)
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Extract payload length
	payloadLen := int(header[1] & 0x7F)

	// Extended payload length
	if payloadLen == 126 {
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(conn, extLen); err != nil {
			return nil, err
		}
		payloadLen = int(extLen[0])<<8 | int(extLen[1])
	} else if payloadLen == 127 {
		extLen := make([]byte, 8)
		if _, err := io.ReadFull(conn, extLen); err != nil {
			return nil, err
		}
		payloadLen = int(extLen[0])<<56 | int(extLen[1])<<48 | int(extLen[2])<<40 | int(extLen[3])<<32 |
			int(extLen[4])<<24 | int(extLen[5])<<16 | int(extLen[6])<<8 | int(extLen[7])
	}

	// Ensure the message is masked (clients **must** send masked messages)
	// isMasked := (header[1] & 0x80) != 0
	// Clients MUST send masked messages; servers MUST NOT.
	// if !isMasked {
	// 	return nil, fmt.Errorf("invalid WebSocket frame: MASK must be clear")
	// }

	// Read masking key
	maskKey := make([]byte, 4)
	if _, err := io.ReadFull(conn, maskKey); err != nil {
		return nil, err
	}

	// Read payload data
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	// Unmask payload
	for i := 0; i < payloadLen; i++ {
		payload[i] ^= maskKey[i%4]
	}

	return payload, nil
}

func writeFrame(conn io.Writer, message []byte) error {
	// Determine the payload length encoding
	var header []byte
	payloadLen := len(message)

	if payloadLen <= 125 {
		header = []byte{0x81, byte(payloadLen)}
	} else if payloadLen <= 65535 {
		header = []byte{0x81, 126, byte(payloadLen >> 8), byte(payloadLen & 0xFF)}
	} else {
		header = []byte{0x81, 127,
			byte(payloadLen >> 56), byte(payloadLen >> 48), byte(payloadLen >> 40), byte(payloadLen >> 32),
			byte(payloadLen >> 24), byte(payloadLen >> 16), byte(payloadLen >> 8), byte(payloadLen & 0xFF)}
	}

	// Write header and payload
	_, err := conn.Write(append(header, message...))
	return err
}

func handleWebSocket(conn io.ReadWriteCloser, handler WSHandler) {
	defer conn.Close()

	wsConn := WSConn{conn: conn}
	handler.OnConnect(wsConn)
	defer handler.OnClose(wsConn)

	done := make(chan struct{})

	go pingLoop(conn, done)

	for {
		msg, err := readFrame(conn)
		if err != nil {
			handler.OnError(err)
			break
		}

		handler.OnMessage(wsConn, string(msg))
	}

	close(done)
}

