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
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/drewwalton19216801/tailutils"
)

// Client represents a connected client with its associated ID, connection, public key, and shared secret.
type Client struct {
	ID           string
	Conn         net.Conn
	PublicKey    *ecdh.PublicKey
	SharedSecret []byte
}

var (
	clients        = make(map[string]*Client) // clients stores the connected clients indexed by their ID.
	clientMutex    = sync.RWMutex{}           // mutex synchronizes access to the clients map.
	serverPrivKey  *ecdh.PrivateKey           // serverPrivKey is the server's ECDH private key.
	serverPubKey   *ecdh.PublicKey            // serverPubKey is the server's ECDH public key.
	operatorID     string                     // Store the operator's ID
	operatorMutex  = sync.RWMutex{}           // Mutex for operator operations
	listenerWG     sync.WaitGroup             // WaitGroup for listeners
	shutdownSignal = make(chan struct{})      // Channel to signal shutdown
	bannedClients  = make(map[string]bool)    // Store banned clients
	banMutex       = sync.RWMutex{}           // Mutex for ban operations
)

// isOperator returns true if the provided client ID is the operator's ID, false otherwise.
func isOperator(clientID string) bool {
	operatorMutex.RLock()
	defer operatorMutex.RUnlock()
	return clientID == operatorID
}

// isBanned returns true if the provided client ID is banned, false otherwise.
func isBanned(clientID string) bool {
	banMutex.RLock()
	defer banMutex.RUnlock()
	return bannedClients[clientID]
}

// handleOperatorCommand processes an operator command and takes the appropriate action.
//
// The following commands are supported:
//
// - KICK <clientID>: Kicks the specified client from the server.
func handleOperatorCommand(command, senderID string, args []string, conn net.Conn) {
	if !isOperator(senderID) {
		conn.Write([]byte("ERROR Not authorized as operator\n"))
		return
	}

	switch command {
	case "KICK":
		if len(args) != 1 {
			conn.Write([]byte("ERROR Usage: KICK <clientID>\n"))
			return
		}
		targetID := args[0]

		// Don't allow kicking the operator
		if targetID == operatorID {
			conn.Write([]byte("ERROR Cannot kick the operator\n"))
			return
		}

		clientMutex.Lock()
		if client, exists := clients[targetID]; exists {
			client.Conn.Write([]byte("KICKED You have been kicked by the operator\n"))
			client.Conn.Close()
			delete(clients, targetID)
			conn.Write([]byte(fmt.Sprintf("SUCCESS Kicked client %s\n", targetID)))
		} else {
			conn.Write([]byte(fmt.Sprintf("ERROR Client %s not found\n", targetID)))
		}
		clientMutex.Unlock()
	case "BAN":
		if len(args) != 1 {
			conn.Write([]byte("ERROR Usage: BAN <clientID>\n"))
			return
		}
		targetID := args[0]
		if targetID == operatorID {
			conn.Write([]byte("ERROR Cannot ban the operator\n"))
			return
		}
		banMutex.Lock()
		bannedClients[targetID] = true
		banMutex.Unlock()
		clientMutex.Lock()
		if client, exists := clients[targetID]; exists {
			client.Conn.Write([]byte("BANNED You have been banned by the operator\n"))
			client.Conn.Close()
			delete(clients, targetID)
		}
		clientMutex.Unlock()
		conn.Write([]byte(fmt.Sprintf("SUCCESS Banned client %s\n", targetID)))
	case "UNBAN":
		if len(args) != 1 {
			conn.Write([]byte("ERROR Usage: UNBAN <clientID>\n"))
			return
		}
		targetID := args[0]
		banMutex.Lock()
		if _, exists := bannedClients[targetID]; exists {
			delete(bannedClients, targetID)
			conn.Write([]byte(fmt.Sprintf("SUCCESS Unbanned client %s\n", targetID)))
		} else {
			conn.Write([]byte(fmt.Sprintf("ERROR Client %s not found in banned list\n", targetID)))
		}
		banMutex.Unlock()
	case "LISTBANS":
		conn.Write([]byte("BEGIN_RESPONSE\n"))
		banMutex.RLock()
		if len(bannedClients) == 0 {
			conn.Write([]byte("No clients are currently banned\n"))
		} else {
			for clientID := range bannedClients {
				conn.Write([]byte(fmt.Sprintf("BANNED %s\n", clientID)))
			}
		}
		banMutex.RUnlock()
		conn.Write([]byte("END_RESPONSE\n"))
	default:
		conn.Write([]byte("ERROR Unknown operator command\n"))
	}
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
			if len(args) == 1 {
				clientIDCandidate := args[0]
				if isBanned(clientIDCandidate) {
					conn.Write([]byte("ERROR You are banned from this server\n"))
					return
				}
				clientMutex.RLock()
				_, ok := clients[clientIDCandidate]
				clientsEmpty := len(clients) == 0
				clientMutex.RUnlock()

				if ok {
					conn.Write([]byte("ERROR Client name already registered\n"))
					continue
				}

				clientID = clientIDCandidate
				clientMutex.Lock()
				clients[clientID] = &Client{ID: clientID, Conn: conn}
				clientMutex.Unlock()

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

				pubKeyBytes := serverPubKey.Bytes()
				conn.Write([]byte("PUBLICKEY\n"))
				conn.Write([]byte(hex.EncodeToString(pubKeyBytes) + "\n"))
				conn.Write([]byte("END PUBLICKEY\n"))
			} else {
				conn.Write([]byte("ERROR Invalid REGISTER command\n"))
			}
		case "KICK":
			if len(args) >= 1 {
				handleOperatorCommand("KICK", clientID, args, conn)
			} else {
				conn.Write([]byte("ERROR Invalid KICK command\n"))
			}
		case "BAN":
			if len(args) >= 1 {
				handleOperatorCommand("BAN", clientID, args, conn)
			} else {
				conn.Write([]byte("ERROR Invalid BAN command\n"))
			}
		case "UNBAN":
			if len(args) >= 1 {
				handleOperatorCommand("UNBAN", clientID, args, conn)
			} else {
				conn.Write([]byte("ERROR Invalid UNBAN command\n"))
			}
		case "LISTBANS":
			handleOperatorCommand("LISTBANS", clientID, args, conn)
		case "CLIENTPUBKEY":
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

			sharedSecret, err := serverPrivKey.ECDH(clientPubKey)
			if err != nil {
				fmt.Println("Error computing shared secret:", err)
				return
			}

			hashedSecret := sha256.Sum256(sharedSecret)
			clientMutex.Lock()
			if client, exists := clients[clientID]; exists {
				client.PublicKey = clientPubKey
				client.SharedSecret = hashedSecret[:]
			}
			clientMutex.Unlock()
		case "SEND":
			if len(args) == 2 {
				recipientID := args[0]
				encryptedDataHex := args[1]

				if recipientID == "ALL" {
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
					handleBroadcast(clientID, string(plaintext))
					conn.Write([]byte("BROADCAST SENT\n"))
				} else {
					sendMessageToClient(clientID, recipientID, encryptedDataHex)
				}
			} else {
				conn.Write([]byte("ERROR Invalid SEND command\n"))
			}
		case "LIST":
			conn.Write([]byte("BEGIN_RESPONSE\n"))
			clientMutex.RLock()
			for _, client := range clients {
				conn.Write([]byte(fmt.Sprintf("CLIENT %s\n", client.ID)))
			}
			clientMutex.RUnlock()
			conn.Write([]byte("END_RESPONSE\n"))
		case "INFO":
			tailscaleIP4, ip4err := tailutils.GetTailscaleIP()
			tailscaleIP6, ip6err := tailutils.GetTailscaleIP6()
			tailscaleIP := ""

			if ip4err == nil && ip6err == nil {
				tailscaleIP = fmt.Sprintf("%s, %s", tailscaleIP4, tailscaleIP6)
			} else if ip4err == nil {
				tailscaleIP = tailscaleIP4
			} else if ip6err == nil {
				tailscaleIP = tailscaleIP6
			}

			if ip4err != nil && ip6err != nil {
				conn.Write([]byte("INFO No Tailscale IP\n"))
			} else {
				conn.Write([]byte(fmt.Sprintf("INFO Tailscale IP(s): %s\n", tailscaleIP)))
			}
		case "SERVERHELP":
			// Determine if the client is an operator
			operatorStatus := isOperator(clientID)
			// Send BEGIN_RESPONSE marker
			conn.Write([]byte("BEGIN_RESPONSE\n"))
			// Send the help text
			helpText := printServerCommands(operatorStatus)
			conn.Write([]byte(helpText))
			// Send END_RESPONSE marker
			conn.Write([]byte("END_RESPONSE\n"))
		default:
			conn.Write([]byte("ERROR Unknown command: " + message + "\n"))
		}
	}
}

// sendMessageToClient sends an encrypted message from the sender to the specified recipient.
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

// handleBroadcast sends a broadcast message from the sender to all other connected clients.
func handleBroadcast(senderID, messageText string) {
	clientMutex.RLock()
	recipients := make([]*Client, 0, len(clients))
	for id, client := range clients {
		if id != senderID {
			recipients = append(recipients, client)
		}
	}
	clientMutex.RUnlock()

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
func printServerCommands(isOperator bool) string {
	var helptext string

	helptext += "Available server commands:\n"
	helptext += "LIST - List all connected clients\n"
	helptext += "INFO - Print server information\n"

	if isOperator {
		helptext += "Operator commands:\n"
		helptext += "KICK <clientID> - Kick a client from the server\n"
		helptext += "BAN <clientID> - Ban a client from the server\n"
		helptext += "UNBAN <clientID> - Unban a client from the server\n"
		helptext += "LISTBANS - List all banned clients\n"
	}

	helptext += "END SERVERHELP\n"

	return helptext
}

// startListener starts a TCP listener on the specified network and address.
func startListener(network, address string) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("Server is listening on %s (%s)...\n", address, network)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-shutdownSignal:
				return nil
			default:
				fmt.Printf("Error accepting %s connection: %v\n", network, err)
				continue
			}
		}
		go handleClient(conn)
	}
}

// main is the entry point of the server program.
func main() {
	// Define command-line flags
	var ipv4Flag, ipv6Flag bool
	flag.BoolVar(&ipv4Flag, "ipv4", false, "Enable IPv4 mode")
	flag.BoolVar(&ipv6Flag, "ipv6", false, "Enable IPv6 mode")
	flag.Parse()

	// Determine modes based on flags
	if !ipv4Flag && !ipv6Flag {
		ipv4Flag = true
		fmt.Println("No mode specified, defaulting to IPv4")
	} else {
		if ipv4Flag && ipv6Flag {
			fmt.Println("Running in both IPv4 and IPv6 modes")
		} else if ipv4Flag {
			fmt.Println("Running in IPv4 mode")
		} else if ipv6Flag {
			fmt.Println("Running in IPv6 mode")
		}
	}

	var err error
	// Generate ECDH key pair
	serverPrivKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating ECDH key:", err)
		return
	}
	serverPubKey = serverPrivKey.PublicKey()

	// Initialize WaitGroup
	listenerWG = sync.WaitGroup{}

	// Start listeners based on the selected modes
	if ipv4Flag {
		ip4, err := tailutils.GetTailscaleIP()
		if err != nil {
			fmt.Println("Error getting Tailscale IPv4:", err)
			return
		}
		address4 := ip4 + ":12345" // Use port 12345 or any available port
		listenerWG.Add(1)
		go func() {
			defer listenerWG.Done()
			err := startListener("tcp4", address4)
			if err != nil {
				fmt.Printf("IPv4 listener error: %v\n", err)
			}
		}()
	}

	if ipv6Flag {
		ip6, err := tailutils.GetTailscaleIP6()
		if err != nil {
			fmt.Println("Error getting Tailscale IPv6:", err)
			return
		}
		// Enclose IPv6 address in brackets
		address6 := fmt.Sprintf("[%s]:12345", ip6)
		listenerWG.Add(1)
		go func() {
			defer listenerWG.Done()
			err := startListener("tcp6", address6)
			if err != nil {
				fmt.Printf("IPv6 listener error: %v\n", err)
			}
		}()
	}

	// Wait for all listeners to finish (which is never, unless shutdown)
	listenerWG.Wait()
}
