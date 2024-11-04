package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
)

// getTailscaleIP function as provided
func getTailscaleIP() (string, error) {
	// Get the IP address of the Tailscale interface
	iface, err := net.InterfaceByName("tailscale0")
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no Tailscale IP address found")
}

type Client struct {
	ID   string
	Conn net.Conn
}

var (
	clients = make(map[string]*Client)
	mutex   = &sync.Mutex{}
)

func handleClient(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	var clientID string

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Client %s disconnected.\n", clientID)
			if clientID != "" {
				mutex.Lock()
				delete(clients, clientID)
				mutex.Unlock()
			}
			return
		}

		message = strings.TrimSpace(message)
		fmt.Printf("Received from %s: %s\n", clientID, message)

		if strings.HasPrefix(message, "REGISTER") {
			parts := strings.Split(message, " ")
			if len(parts) == 2 {
				clientID = parts[1]
				mutex.Lock()
				clients[clientID] = &Client{ID: clientID, Conn: conn}
				mutex.Unlock()
				conn.Write([]byte("REGISTERED\n"))
				fmt.Printf("Client registered: %s\n", clientID)
			} else {
				conn.Write([]byte("ERROR Invalid REGISTER command\n"))
			}
		} else if strings.HasPrefix(message, "SEND") {
			parts := strings.SplitN(message, " ", 3)
			if len(parts) == 3 {
				recipientID := parts[1]
				encryptedMessage := parts[2]

				// Validate message format
				if !strings.Contains(encryptedMessage, "|") {
					conn.Write([]byte("ERROR Invalid message format\n"))
					fmt.Printf("Invalid message format from %s. Disconnecting client.\n", clientID)
					conn.Close()
					return
				}

				// Check if the recipient exists
				mutex.Lock()
				recipient, exists := clients[recipientID]
				mutex.Unlock()
				if exists {
					// Forward the encrypted message to the recipient
					recipient.Conn.Write([]byte(fmt.Sprintf("MESSAGE from %s: %s\n", clientID, encryptedMessage)))
					conn.Write([]byte("MESSAGE SENT\n"))
				} else {
					conn.Write([]byte("ERROR Recipient not found\n"))
				}
			} else {
				conn.Write([]byte("ERROR Invalid SEND command\n"))
			}
		} else {
			conn.Write([]byte("ERROR Unknown command\n"))
		}
	}
}

func main() {
	// Use getTailscaleIP to get the Tailscale IP address
	ip, err := getTailscaleIP()
	if err != nil {
		fmt.Println("Error getting Tailscale IP:", err)
		return
	}
	address := ip + ":12345" // Use port 12345 or any available port

	ln, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer ln.Close()
	fmt.Printf("Server is listening on %s...\n", address)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleClient(conn)
	}
}
