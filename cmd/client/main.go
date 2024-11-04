package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// Check if the local IP address belongs to a Tailscale interface
func tailscaleRunning() bool {
	// Check if the local IP address belongs to a Tailscale interface
	iface, err := net.InterfaceByName("tailscale0")
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return true
			}
		}
	}
	return false
}

// OTP encryption (XOR cipher)
func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}

func readMessages(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Disconnected from server.")
			return
		}
		message = strings.TrimSpace(message)
		if strings.HasPrefix(message, "MESSAGE from") {
			parts := strings.SplitN(message, ": ", 2)
			senderInfo := parts[0]
			encryptedData := parts[1]

			// Extract sender ID
			senderID := strings.TrimPrefix(senderInfo, "MESSAGE from ")

			// Validate the encrypted data format
			if !strings.Contains(encryptedData, "|") {
				fmt.Printf("\rReceived malformed message from %s. Ignoring.\n> ", senderID)
				continue
			}

			// Encrypted data format: key_hex|ciphertext_hex
			dataParts := strings.SplitN(encryptedData, "|", 2)
			if len(dataParts) != 2 {
				fmt.Println("Invalid message format.")
				continue
			}
			keyHex := dataParts[0]
			ciphertextHex := dataParts[1]

			// Decode hex strings
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				fmt.Println("Error decoding key:", err)
				continue
			}
			ciphertext, err := hex.DecodeString(ciphertextHex)
			if err != nil {
				fmt.Println("Error decoding ciphertext:", err)
				continue
			}

			// Decrypt the message
			if len(key) != len(ciphertext) {
				fmt.Println("Key and ciphertext lengths do not match.")
				continue
			}
			plaintext := encrypt(ciphertext, key)
			fmt.Printf("\rMessage from %s: %s\n> ", senderID, string(plaintext))
		} else {
			fmt.Println("\r" + message)
			fmt.Print("> ")
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run client.go <YourID>")
		return
	}
	clientID := os.Args[1]

	// Ensure Tailscale is running
	if !tailscaleRunning() {
		fmt.Println("Tailscale is not running. Please start it and try again.")
		return
	}

	// You need to know the server's Tailscale IP. Here we'll assume you have it.
	// Alternatively, you could discover it or pass it as an argument.
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run client.go <YourID> <ServerTailscaleIP>")
		return
	}
	serverIP := os.Args[2]
	address := serverIP + ":12345"

	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	// Register with the server
	fmt.Fprintf(conn, "REGISTER %s\n", clientID)
	fmt.Println("Connected to the server. Type your commands below:")
	fmt.Print("> ")

	// Start a goroutine to read messages from the server
	go readMessages(conn)

	// Read user input and send to the server
	stdinReader := bufio.NewReader(os.Stdin)
	for {
		input, err := stdinReader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			return
		}
		input = strings.TrimSpace(input)

		// Check for exit or quit commands, in any combination of case
		if strings.HasPrefix(input, "exit") || strings.HasPrefix(input, "quit") {
			return
		}

		if strings.HasPrefix(input, "SEND") {
			// Expected format: SEND <RecipientID> <Message>
			parts := strings.SplitN(input, " ", 3)
			if len(parts) != 3 {
				fmt.Println("Invalid SEND command. Use: SEND <RecipientID> <Message>")
				continue
			}
			recipientID := parts[1]
			messageText := parts[2]

			// Generate OTP key
			key := make([]byte, len(messageText))
			_, err := rand.Read(key)
			if err != nil {
				fmt.Println("Error generating OTP key:", err)
				continue
			}

			// Encrypt the message
			plaintext := []byte(messageText)
			ciphertext := encrypt(plaintext, key)

			// Encode key and ciphertext in hex
			keyHex := hex.EncodeToString(key)
			ciphertextHex := hex.EncodeToString(ciphertext)

			// Send the encrypted message in the format: SEND <RecipientID> <key_hex>|<ciphertext_hex>
			encryptedData := keyHex + "|" + ciphertextHex
			fmt.Fprintf(conn, "SEND %s %s\n", recipientID, encryptedData)
		} else {
			fmt.Println("Unknown command. Use 'SEND <RecipientID> <Message>'")
		}
		fmt.Print("> ")
	}
}
