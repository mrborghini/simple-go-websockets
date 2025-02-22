// Example of a simple WebSocket server using the simple-go-websockets
package main

import (
	"github.com/mrborghini/simple-go-websockets/server"
	"log"
	"net/http"
)

type MyWSHandler struct{}

func (h *MyWSHandler) OnMessage(conn server.WSConn, message string) {
	log.Printf("A new message: %s\n", message)
	// Send message back to client
	conn.Send(message)
}

func (h *MyWSHandler) OnClose(conn server.WSConn) {
	log.Println("Handler detected WebSocket closure")
}

func (h *MyWSHandler) OnError(err error) {
	log.Printf("Handler encountered error: %v\n", err)
}

func (h *MyWSHandler) OnConnect(conn server.WSConn) {
	log.Println("Handler detected new WebSocket connection")
}

func main() {
	// Create a new WebSocket server with the http endpoint /ws
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handler := &MyWSHandler{}
		server.UpgradeToWebSocket(w, r, handler)
	})
	// Start listening on port 8080
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
