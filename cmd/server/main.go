// Package main implements a secure TCP server that communicates over a Tailscale network.
// The server uses ECDH key exchange to establish shared secrets with clients for encrypted communication.
// Clients can register with the server, exchange public keys, and send encrypted messages to other clients.
// The server supports commands such as REGISTER, SEND, LIST, INFO, and SERVERHELP.
//
// To run the server, ensure that you have Tailscale installed and configured.
// The server will automatically detect its Tailscale IP address and listen on port 12345.
// Clients can connect to the server using the Tailscale IP address and communicate using the defined protocol.
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Client represents a connected client with its associated ID, connection, public key, and shared secret.
type Client struct {
	ID           string
	Conn         net.Conn
	PublicKey    *ecdh.PublicKey
	SharedSecret []byte
}

var (
	clients       = make(map[string]*Client) // clients stores the connected clients indexed by their ID.
	mutex         = &sync.Mutex{}            // mutex synchronizes access to the clients map.
	serverPrivKey *ecdh.PrivateKey           // serverPrivKey is the server's ECDH private key.
	serverPubKey  *ecdh.PublicKey            // serverPubKey is the server's ECDH public key.
)

// getTailscaleIP retrieves the IP address within the Tailscale network (100.64.0.0/10).
func getTailscaleIP() (string, error) {
	// Define the Tailscale IP range
	_, tsNet, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return "", fmt.Errorf("failed to parse Tailscale CIDR: %v", err)
	}

	// Get a list of all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, iface := range interfaces {
		// Skip interfaces that are down or are loopback interfaces
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}

		// Get all addresses associated with the interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue // If we can't get addresses, skip this interface
		}

		for _, addr := range addrs {
			// Check if the address is an IPNet
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			// Consider only IPv4 addresses
			if ip.To4() == nil {
				continue
			}

			// Check if the IP is within the Tailscale network
			if tsNet.Contains(ip) {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no Tailscale IP address found")
}

// handleClient handles communication with a connected client over the given net.Conn.
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

				// Send the server's public key to the client
				pubKeyBytes := serverPubKey.Bytes()
				conn.Write([]byte("PUBLICKEY\n"))
				conn.Write([]byte(hex.EncodeToString(pubKeyBytes) + "\n"))
				conn.Write([]byte("END PUBLICKEY\n"))
			} else {
				conn.Write([]byte("ERROR Invalid REGISTER command\n"))
			}
		} else if strings.HasPrefix(message, "CLIENTPUBKEY") {
			// Client is sending its public key
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

			// Compute shared secret
			sharedSecret, err := serverPrivKey.ECDH(clientPubKey)
			if err != nil {
				fmt.Println("Error computing shared secret:", err)
				return
			}
			// Hash the shared secret to derive a key
			hashedSecret := sha256.Sum256(sharedSecret)

			// Store the client's public key and shared secret
			mutex.Lock()
			if client, exists := clients[clientID]; exists {
				client.PublicKey = clientPubKey
				client.SharedSecret = hashedSecret[:]
			}
			mutex.Unlock()
		} else if strings.HasPrefix(message, "SEND") {
			parts := strings.SplitN(message, " ", 3)
			if len(parts) == 3 {
				recipientID := parts[1]
				encryptedDataHex := parts[2]
				if recipientID == "ALL" {
					// Decrypt the message using the shared secret
					mutex.Lock()
					client := clients[clientID]
					mutex.Unlock()
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
					// Now handle the broadcast with the plaintext message
					handleBroadcast(clientID, string(plaintext))
					conn.Write([]byte("BROADCAST SENT\n"))
				} else {
					sendMessageToClient(clientID, recipientID, encryptedDataHex)
				}
			} else {
				conn.Write([]byte("ERROR Invalid SEND command\n"))
			}
		} else if strings.HasPrefix(message, "LIST") {
			// List all connected clients
			mutex.Lock()
			for _, client := range clients {
				conn.Write([]byte(fmt.Sprintf("CLIENT %s\n", client.ID)))
			}
			mutex.Unlock()
			conn.Write([]byte("LISTED\n"))
		} else if strings.HasPrefix(message, "INFO") {
			// Print server information
			tailscaleIP, err := getTailscaleIP()
			if err != nil {
				conn.Write([]byte("ERROR Failed to get Tailscale IP: " + err.Error() + "\n"))
			} else {
				conn.Write([]byte(fmt.Sprintf("INFO Tailscale IP: %s\n", tailscaleIP)))

				// Print connected clients
				mutex.Lock()
				for _, client := range clients {
					conn.Write([]byte(fmt.Sprintf("CLIENT %s\n", client.ID)))
				}
				mutex.Unlock()

				// Print server commands
				conn.Write([]byte(printServerCommands()))
				conn.Write([]byte("INFO LISTED\n"))
			}
		} else if strings.HasPrefix(message, "SERVERHELP") {
			// Print server commands
			conn.Write([]byte(printServerCommands()))
			conn.Write([]byte("SERVERHELP LISTED\n"))
		} else {
			conn.Write([]byte("ERROR Unknown command: " + message + "\n"))
		}
	}
}

// sendMessageToClient sends an encrypted message from the sender to the specified recipient.
func sendMessageToClient(senderID, recipientID, encryptedData string) {
	mutex.Lock()
	recipient, exists := clients[recipientID]
	mutex.Unlock()
	if exists {
		recipient.Conn.Write([]byte(fmt.Sprintf("MESSAGE from %s: %s\n", senderID, encryptedData)))
	} else {
		sender, exists := clients[senderID]
		if exists {
			sender.Conn.Write([]byte("ERROR Recipient not found\n"))
		}
	}
}

// handleBroadcast sends a broadcast message from the sender to all other connected clients.
func handleBroadcast(senderID, messageText string) {
	mutex.Lock()
	recipients := make([]*Client, 0, len(clients))
	for id, client := range clients {
		if id != senderID {
			recipients = append(recipients, client)
		}
	}
	mutex.Unlock()

	// For each recipient, generate a unique OTP key and encrypt the message
	for _, recipient := range recipients {
		key := make([]byte, len(messageText))
		_, err := rand.Read(key)
		if err != nil {
			fmt.Printf("Error generating OTP key for %s: %v\n", recipient.ID, err)
			continue
		}

		// Encrypt the message
		plaintext := []byte(messageText)
		ciphertext := encrypt(plaintext, key)

		// Encode key and ciphertext in hex
		keyHex := hex.EncodeToString(key)
		ciphertextHex := hex.EncodeToString(ciphertext)

		// Send the encrypted message to the recipient
		encryptedData := keyHex + "|" + ciphertextHex
		recipient.Conn.Write([]byte(fmt.Sprintf("BROADCAST from %s: %s\n", senderID, encryptedData)))
	}
}

// decryptAES decrypts the given ciphertext using AES encryption with the provided key.
func decryptAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	// Remove padding
	padLen := int(decrypted[len(decrypted)-1])
	if padLen > len(decrypted) {
		return nil, fmt.Errorf("invalid padding")
	}
	return decrypted[:len(decrypted)-padLen], nil
}

// encrypt performs a simple XOR encryption of the message using the provided key.
func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}

// printServerCommands returns a string containing the list of available server commands.
func printServerCommands() string {
	var helptext string

	helptext += "Available server commands:\n"
	helptext += "LIST - List all connected clients\n"
	helptext += "INFO - Print server information\n"
	helptext += "SERVERHELP - Print this help text\n"

	return helptext
}

// main is the entry point of the server program.
func main() {
	var err error
	// Generate ECDH key pair
	serverPrivKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating ECDH key:", err)
		return
	}
	serverPubKey = serverPrivKey.PublicKey()

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
