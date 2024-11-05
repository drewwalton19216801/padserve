package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// Check if the local IP address belongs to a Tailscale interface and is not a link-local address
func isTailscale() (bool, error) {
	// Determine the Tailscale interface name based on the OS
	var ifaceName string
	if runtime.GOOS == "windows" {
		ifaceName = "Tailscale" // Typical interface name for Tailscale on Windows
	} else {
		ifaceName = "tailscale0" // Interface name on Linux
	}

	// Check if the local IP address belongs to a Tailscale interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
			if ipnet.IP.To4() != nil {
				return true, nil
			}
		}
	}
	return false, nil
}

// OTP encryption (XOR cipher)
func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}

func readMessages(conn net.Conn, done chan bool) {
	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Disconnected from server.")
			done <- true // Signal main function to exit
			return
		}
		message = strings.TrimSpace(message)
		if strings.HasPrefix(message, "MESSAGE from") || strings.HasPrefix(message, "BROADCAST from") {
			parts := strings.SplitN(message, ": ", 2)
			senderInfo := parts[0]
			encryptedData := parts[1]

			// Extract sender ID
			var senderID string
			if strings.HasPrefix(senderInfo, "MESSAGE from") {
				senderID = strings.TrimPrefix(senderInfo, "MESSAGE from ")
			} else if strings.HasPrefix(senderInfo, "BROADCAST from") {
				senderID = strings.TrimPrefix(senderInfo, "BROADCAST from ")
			}

			// Encrypted data format: key_hex|ciphertext_hex
			dataParts := strings.SplitN(encryptedData, "|", 2)
			if len(dataParts) != 2 {
				fmt.Printf("\rInvalid message format from %s. Ignoring.\n> ", senderID)
				continue
			}
			keyHex := dataParts[0]
			ciphertextHex := dataParts[1]

			// Decode hex strings
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				fmt.Printf("\rError decoding key from %s: %v\n> ", senderID, err)
				continue
			}
			ciphertext, err := hex.DecodeString(ciphertextHex)
			if err != nil {
				fmt.Printf("\rError decoding ciphertext from %s: %v\n> ", senderID, err)
				continue
			}

			// Decrypt the message
			if len(key) != len(ciphertext) {
				fmt.Printf("\rKey and ciphertext lengths do not match from %s.\n> ", senderID)
				continue
			}
			plaintext := encrypt(ciphertext, key)
			if strings.HasPrefix(senderInfo, "MESSAGE from") {
				fmt.Printf("\rMessage from %s: %s\n> ", senderID, string(plaintext))
			} else if strings.HasPrefix(senderInfo, "BROADCAST from") {
				fmt.Printf("\rBroadcast from %s: %s\n> ", senderID, string(plaintext))
			}
		} else {
			fmt.Println("\r" + message)
			fmt.Print("> ")
		}
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run client.go <YourID> <ServerTailscaleIP>")
		return
	}
	clientID := os.Args[1]
	serverIP := os.Args[2]
	address := serverIP + ":12345"

	// Check if the local IP address belongs to a Tailscale interface
	isTailscale, err := isTailscale()
	if err != nil {
		fmt.Println("Error checking local IP address:", err)
		return
	}
	if !isTailscale {
		fmt.Println("Please connect to a Tailscale network.")
		return
	}

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

	// Channel to signal when to exit
	done := make(chan bool)

	// Start a goroutine to read messages from the server
	go readMessages(conn, done)

	// Start a goroutine to read user input
	inputChan := make(chan string)
	go func() {
		stdinReader := bufio.NewReader(os.Stdin)
		for {
			input, err := stdinReader.ReadString('\n')
			if err != nil {
				fmt.Println("Error reading input:", err)
				close(inputChan)
				return
			}
			input = strings.TrimSpace(input)
			inputChan <- input
		}
	}()

	// Main loop to handle user input and exit signal
	for {
		select {
		case <-done:
			fmt.Println("Exiting...")
			return
		case input, ok := <-inputChan:
			if !ok {
				fmt.Println("Input channel closed.")
				return
			}
			if strings.HasPrefix(input, "SEND") {
				// Expected format:
				// - To a client: SEND <RecipientID> <Message>
				// - To all: SEND ALL <Message>
				parts := strings.SplitN(input, " ", 3)
				if len(parts) != 3 {
					fmt.Println("Invalid SEND command. Use: SEND <RecipientID|ALL> <Message>")
					fmt.Print("> ")
					continue
				}
				recipientID := parts[1]
				messageText := parts[2]

				if recipientID == "ALL" {
					// Send plaintext to server for broadcast
					fmt.Fprintf(conn, "SEND ALL %s\n", messageText)
				} else {
					// Generate OTP key
					key := make([]byte, len(messageText))
					_, err := rand.Read(key)
					if err != nil {
						fmt.Println("Error generating OTP key:", err)
						fmt.Print("> ")
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
				}
			} else {
				fmt.Println("Unknown command. Use 'SEND <RecipientID|ALL> <Message>'")
			}
			fmt.Print("> ")
		}
	}
}
