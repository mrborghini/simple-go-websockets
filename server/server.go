package server

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
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

func readFrame(conn io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Extract payload length
	payloadLen := int(header[1] & 0x7F)
	if payloadLen == 126 {
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(conn, extLen); err != nil {
			return nil, err
		}
		payloadLen = int(extLen[0])<<8 | int(extLen[1])
	} else if payloadLen == 127 {
		return nil, fmt.Errorf("WebSocket frame too large")
	}

	// Check if the message is masked
	isMasked := (header[1] & 0x80) != 0
	var maskKey [4]byte

	// Clients **MUST** mask their messages; servers **MUST NOT**.
	// If the message is from a client, we must unmask it.
	if isMasked {
		if _, err := io.ReadFull(conn, maskKey[:]); err != nil {
			return nil, err
		}
	}

	// Read payload data
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	// Unmask only if the message is masked
	if isMasked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}

func writeFrame(conn io.Writer, message []byte) error {
	// WebSocket text frame: FIN=1, RSV=000, Opcode=0001 (text)
	header := []byte{0x81, byte(len(message))}

	// Write header and payload
	_, err := conn.Write(append(header, message...))
	return err
}

func handleWebSocket(conn io.ReadWriteCloser, handler WSHandler) {
	defer conn.Close()

	// Notify the handler that a client has connected
	defer handler.OnClose(WSConn{conn: conn})

	for {
		msg, err := readFrame(conn)
		if err != nil {
			handler.OnError(err)
			break
		}

		handler.OnMessage(WSConn{conn: conn}, string(msg)) // Notify the handler of the received message
	}
}
