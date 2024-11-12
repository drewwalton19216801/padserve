// Package main implements a secure TCP server that communicates over a Tailscale network.
// The server facilitates encrypted communication between clients using ECDH key exchange and AES encryption.
// Clients can register with the server, exchange public keys, and send encrypted messages to other clients or broadcast messages to all clients.
// The server supports commands such as REGISTER, SEND, LIST, INFO, and SERVERHELP.
// The first client to register becomes the operator and can issue operator commands such as KICK, BAN, UNBAN, and LISTBANS.
//
// The server can be run in IPv4 and/or IPv6 mode, based on command-line flags (-ipv4 and -ipv6).
// To run the server, ensure that you have Tailscale installed and configured.
// The server will automatically detect its Tailscale IP address and listen on port 12345.
// Clients can connect to the server using the Tailscale IP address or hostname, and communicate using the defined protocol.
//
// Commands:
//   - REGISTER <clientID>: Registers a new client with the given ID.
//   - SEND <recipientID> <encryptedData>: Sends an encrypted message to the specified recipient.
//     Use recipientID "ALL" to send a broadcast message to all clients.
//   - LIST: Lists all connected clients.
//   - INFO: Displays server information.
//   - SERVERHELP: Displays a list of available server commands.
//
// Operator Commands (available to the operator client):
// - KICK <clientID>: Kicks the specified client from the server.
// - BAN <clientID>: Bans the specified client from the server.
// - UNBAN <clientID>: Unbans the specified client.
// - LISTBANS: Lists all banned clients.
//
// Encryption:
// The server uses ECDH key exchange to establish shared secrets with clients.
// All-client messages are encrypted using AES encryption with the shared secret keys.
// For client-to-client messages, the server generates unique one-time keys for each recipient and encrypts the message using a simple XOR cipher.
//
// Notes:
// - The server uses mutexes to synchronize access to shared resources such as the client list and operator ID.
// - The server handles clients in separate goroutines for concurrent communication.
// - The server can be run in IPv4 and/or IPv6 mode by using the -ipv4 and -ipv6 command-line flags.
package main

import (
	"bufio"
	"context"
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

// Client holds information about a connected client, including its unique identifier, network connection,
// ECDH public key, and the shared secret established with the server.
type Client struct {
	ID           string
	Conn         net.Conn
	PublicKey    *ecdh.PublicKey
	SharedSecret []byte
}

var (
	clients       = make(map[string]*Client) // clients maps client IDs to their corresponding Client structures.
	clientMutex   = sync.RWMutex{}           // clientMutex synchronizes access to the clients map.
	serverPrivKey *ecdh.PrivateKey           // serverPrivKey holds the server's ECDH private key.
	serverPubKey  *ecdh.PublicKey            // serverPubKey holds the server's ECDH public key.
	operatorID    string                     // operatorID stores the client ID of the operator.
	operatorMutex = sync.RWMutex{}           // operatorMutex synchronizes access to the operatorID variable.
	listenerWG    sync.WaitGroup             // listenerWG manages synchronization of listener goroutines.
	bannedClients = make(map[string]bool)    // bannedClients maps banned client IDs to a boolean value.
	banMutex      = sync.RWMutex{}           // banMutex synchronizes access to the bannedClients map.
)

// isOperator returns true if the provided client ID is the operator's ID.
func isOperator(clientID string) bool {
	operatorMutex.RLock()
	defer operatorMutex.RUnlock()
	return clientID == operatorID
}

// isBanned returns true if the provided client ID is banned.
func isBanned(clientID string) bool {
	banMutex.RLock()
	defer banMutex.RUnlock()
	return bannedClients[clientID]
}

// handleOperatorCommand processes operator commands issued by the operator client.
// Supported commands include:
// - KICK <clientID>: Disconnects the specified client from the server.
// - BAN <clientID>: Bans the specified client and disconnects them if connected.
// - UNBAN <clientID>: Removes a client from the banned list.
// - LISTBANS: Lists all currently banned clients.
// The function checks if the sender is the operator before executing the command.
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

		// Lock the clients map to safely access and modify it
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
		// Add client to the banned list
		banMutex.Lock()
		bannedClients[targetID] = true
		banMutex.Unlock()
		// Disconnect the client if connected
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
		// Remove client from the banned list
		banMutex.Lock()
		if _, exists := bannedClients[targetID]; exists {
			delete(bannedClients, targetID)
			conn.Write([]byte(fmt.Sprintf("SUCCESS Unbanned client %s\n", targetID)))
		} else {
			conn.Write([]byte(fmt.Sprintf("ERROR Client %s not found in banned list\n", targetID)))
		}
		banMutex.Unlock()
	case "LISTBANS":
		// List all banned clients
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
		case "INFO":
			// Provide server information
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

// handleBroadcast sends a message from the sender to all other connected clients.
// For each recipient, it generates a unique one-time pad (OTP) key of the same length as the message,
// encrypts the message using the XOR cipher with the key, and sends the encrypted data along with the key to the recipient.
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

		// Encrypt the message using XOR cipher
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

// decryptAES decrypts the given ciphertext using AES-CBC mode with the provided key.
// It assumes the ciphertext includes the initialization vector (IV) prepended to the encrypted data.
// It also removes padding added during encryption to ensure the message length is a multiple of the block size.
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

	// Remove padding added during encryption
	padLen := int(decrypted[len(decrypted)-1])
	if padLen > len(decrypted) {
		return nil, fmt.Errorf("invalid padding")
	}
	return decrypted[:len(decrypted)-padLen], nil
}

// encrypt performs a simple XOR encryption of the message using the provided key.
// It assumes that the key and message are of the same length.
func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}

// printServerCommands returns a string containing the list of available server commands.
// If the client is the operator, it includes operator-specific commands.
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
// It accepts incoming connections and spawns a goroutine to handle each client.
func startListener(ctx context.Context, network, address string) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("Server is listening on %s (%s)...\n", address, network)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				fmt.Printf("Error accepting %s connection: %v\n", network, err)
				continue
			}
		}

		// Create a child context for the client
		clientCtx, clientCancel := context.WithCancel(ctx)

		go handleClient(clientCtx, clientCancel, conn)
	}
}

// main initializes the server, parses command-line flags, generates the server's ECDH key pair,
// and starts TCP listeners on the Tailscale IP addresses. It supports IPv4 and/or IPv6 based on the provided flags.
func main() {
	// Define command-line flags
	var ipv4Flag, ipv6Flag bool
	flag.BoolVar(&ipv4Flag, "ipv4", false, "Enable IPv4 mode")
	flag.BoolVar(&ipv6Flag, "ipv6", false, "Enable IPv6 mode")
	flag.Parse()

	// Create a root context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		address4 := ip4 + ":12345" // Use port 12345 (FIXME: make this configurable)
		listenerWG.Add(1)
		go func() {
			defer listenerWG.Done()
			err := startListener(ctx, "tcp4", address4)
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
			err := startListener(ctx, "tcp6", address6)
			if err != nil {
				fmt.Printf("IPv6 listener error: %v\n", err)
			}
		}()
	}

	// Wait for all listeners to finish (which is never, unless shutdown)
	listenerWG.Wait()
}
