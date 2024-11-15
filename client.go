// client.go
// Package main handles client interactions, including registration, messaging, and key exchange.

package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Client holds information about a connected client, including its unique identifier, network connection,
// ECDH public key, and the shared secret established with the server.
type Client struct {
	ID           string
	Conn         net.Conn
	PublicKey    *ecdh.PublicKey
	SharedSecret []byte
}

var (
	clients     = make(map[string]*Client) // clients maps client IDs to their corresponding Client structures.
	clientMutex = sync.RWMutex{}           // clientMutex synchronizes access to the clients map.
)

// handleClient manages the interaction with a single client connection.
// It listens for commands from the client, processes them, and sends responses.
// It handles client registration, public key exchange, message sending, and operator commands.
func handleClient(ctx context.Context, cancel context.CancelFunc, conn net.Conn) {
	defer conn.Close()
	defer cancel()

	// Close the connection when context is done
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	reader := bufio.NewReader(conn)
	var clientID string

	for {
		// Check if context is done
		select {
		case <-ctx.Done():
			fmt.Printf("Client %s context done.\n", clientID)
			return
		default:
		}

		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Client %s disconnected.\n", clientID)
			if clientID != "" {
				clientMutex.Lock()
				delete(clients, clientID)
				clientMutex.Unlock()
			}
			return
		}

		message = strings.TrimSpace(message)
		fmt.Printf("Received from %s: %s\n", clientID, message)

		parts := strings.Split(message, " ")
		command := parts[0]
		args := parts[1:]

		switch command {
		case "REGISTER":
			// Handle client registration
			if len(args) == 1 {
				clientIDCandidate := args[0]
				// Check if the client is banned
				if isBanned(clientIDCandidate) {
					conn.Write([]byte("ERROR You are banned from this server\n"))
					return
				}
				// Check if clientID is already taken
				clientMutex.RLock()
				_, ok := clients[clientIDCandidate]
				clientsEmpty := len(clients) == 0
				clientMutex.RUnlock()

				if ok {
					conn.Write([]byte("ERROR Client name already registered\n"))
					continue
				}

				// Register the client
				clientID = clientIDCandidate
				clientMutex.Lock()
				clients[clientID] = &Client{ID: clientID, Conn: conn}
				clientMutex.Unlock()

				// If this is the first client, assign operator role
				if clientsEmpty {
					operatorMutex.Lock()
					operatorID = clientID
					operatorMutex.Unlock()
					conn.Write([]byte("REGISTERED as operator\n"))
					fmt.Printf("Client registered as operator: %s\n", clientID)
				} else {
					conn.Write([]byte("REGISTERED\n"))
					fmt.Printf("Client registered: %s\n", clientID)
				}

				// Send server's public key to the client
				pubKeyBytes := serverPubKey.Bytes()
				conn.Write([]byte("PUBLICKEY\n"))
				conn.Write([]byte(hex.EncodeToString(pubKeyBytes) + "\n"))
				conn.Write([]byte("END PUBLICKEY\n"))
			} else {
				conn.Write([]byte("ERROR Invalid REGISTER command\n"))
			}
		case "KICK":
			// Handle KICK command from operator
			if len(args) >= 1 {
				handleOperatorCommand("KICK", clientID, args, conn)
			} else {
				conn.Write([]byte("ERROR Invalid KICK command\n"))
			}
		case "BAN":
			// Handle BAN command from operator
			if len(args) >= 1 {
				handleOperatorCommand("BAN", clientID, args, conn)
			} else {
				conn.Write([]byte("ERROR Invalid BAN command\n"))
			}
		case "UNBAN":
			// Handle UNBAN command from operator
			if len(args) >= 1 {
				handleOperatorCommand("UNBAN", clientID, args, conn)
			} else {
				conn.Write([]byte("ERROR Invalid UNBAN command\n"))
			}
		case "LISTBANS":
			// Handle LISTBANS command from operator
			handleOperatorCommand("LISTBANS", clientID, args, conn)
		case "CLIENTPUBKEY":
			// Handle client's public key for ECDH key exchange
			pubKeyHex := ""
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println("Error reading client's public key:", err)
					return
				}
				line = strings.TrimSpace(line)
				if line == "END CLIENTPUBKEY" {
					break
				}
				pubKeyHex += line
			}

			// Decode the client's public key from hex
			clientPubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil {
				fmt.Println("Error decoding client's public key:", err)
				return
			}
			clientPubKey, err := ecdh.P256().NewPublicKey(clientPubKeyBytes)
			if err != nil {
				fmt.Println("Error creating client's public key:", err)
				return
			}

			// Compute the shared secret using ECDH
			sharedSecret, err := serverPrivKey.ECDH(clientPubKey)
			if err != nil {
				fmt.Println("Error computing shared secret:", err)
				return
			}

			// Hash the shared secret using SHA-256
			hashedSecret := sha256.Sum256(sharedSecret)
			// Store the client's public key and shared secret
			clientMutex.Lock()
			if client, exists := clients[clientID]; exists {
				client.PublicKey = clientPubKey
				client.SharedSecret = hashedSecret[:]
			}
			clientMutex.Unlock()

			conn.Write([]byte("CLIENTPUBKEY_RECEIVED\n"))
		case "SEND":
			// Handle sending messages to clients
			if len(args) == 2 {
				recipientID := args[0]
				encryptedDataHex := args[1]

				if recipientID == "ALL" {
					// Handle broadcast message
					clientMutex.RLock()
					client := clients[clientID]
					clientMutex.RUnlock()
					if client == nil || client.SharedSecret == nil {
						conn.Write([]byte("ERROR Shared secret not established\n"))
						continue
					}
					encryptedData, err := hex.DecodeString(encryptedDataHex)
					if err != nil {
						conn.Write([]byte("ERROR Invalid encrypted data\n"))
						continue
					}
					plaintext, err := decryptAES(client.SharedSecret, encryptedData)
					if err != nil {
						conn.Write([]byte("ERROR Decryption failed\n"))
						continue
					}
					// Broadcast the message to all clients
					handleBroadcast(clientID, string(plaintext))
					conn.Write([]byte("BROADCAST SENT\n"))
				} else {
					// Send message to a specific client
					sendMessageToClient(clientID, recipientID, encryptedDataHex)
				}
			} else {
				conn.Write([]byte("ERROR Invalid SEND command\n"))
			}
		case "LIST":
			// List all connected clients
			conn.Write([]byte("BEGIN_RESPONSE\n"))
			clientMutex.RLock()
			for _, client := range clients {
				conn.Write([]byte(fmt.Sprintf("CLIENT %s\n", client.ID)))
			}
			clientMutex.RUnlock()
			conn.Write([]byte("END_RESPONSE\n"))
		case "SERVERINFO":
			// Provide server information
			handleOperatorCommand("SERVERINFO", clientID, args, conn)
		case "SERVERHELP":
			// Provide list of available server commands
			operatorStatus := isOperator(clientID)
			conn.Write([]byte("BEGIN_RESPONSE\n"))
			helpText := printServerCommands(operatorStatus)
			conn.Write([]byte(helpText))
			conn.Write([]byte("END_RESPONSE\n"))
		default:
			conn.Write([]byte("ERROR Unknown command: " + message + "\n"))
		}
	}
}

// sendMessageToClient sends an encrypted message from the sender to the specified recipient.
// It looks up the recipient in the clients map and sends the message if the recipient exists.
func sendMessageToClient(senderID, recipientID, encryptedData string) {
	clientMutex.RLock()
	recipient, exists := clients[recipientID]
	clientMutex.RUnlock()
	if exists {
		recipient.Conn.Write([]byte(fmt.Sprintf("MESSAGE from %s: %s\n", senderID, encryptedData)))
	} else {
		clientMutex.RLock()
		sender, exists := clients[senderID]
		clientMutex.RUnlock()
		if exists {
			sender.Conn.Write([]byte("ERROR Recipient not found\n"))
		}
	}
}
