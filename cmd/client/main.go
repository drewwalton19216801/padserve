// main.go
// Package main initializes the client, handles user input, and manages the main loop of the application.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/drewwalton19216801/tailutils"
)

var (
	isOperator bool   // Flag to track if the client is the operator
	clientID   string // The client's unique identifier
)

func main() {
	if len(os.Args) < 3 {
		consoleLog("Usage: go run client.go <YourID> <TailscaleServer>")
		return
	}
	clientID = os.Args[1]
	serverIP := os.Args[2]
	address := serverIP + ":12345"

	// Check if the local IP address belongs to a Tailscale interface
	isTailscale, err := tailutils.HasTailscaleIP()
	if err != nil {
		consoleLog("Error checking local IP address: %v", err)
		return
	}
	if !isTailscale {
		consoleLog("Please connect to a Tailscale network.")
		return
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		consoleLog("Error connecting to server: %v", err)
		return
	}
	defer conn.Close()

	// Setup client (registration, key exchange)
	hashedSecret, err := setupClient(conn, clientID)
	if err != nil {
		consoleLog("Error during client setup: %v", err)
		return
	}

	consoleLog("Connected to the server. Type your commands below:")
	if isOperator {
		consoleLog("You are the server operator. Type HELP to see available commands.")
	} else {
		consoleLog("Type HELP to see available commands.")
	}
	printPrompt()

	// Channel to signal when to exit
	done := make(chan bool)

	// Start a goroutine to read messages from the server
	go readMessages(conn, done)

	// Start a goroutine to read user input from the console
	inputChan := make(chan string)
	go func() {
		stdinReader := bufio.NewReader(os.Stdin)
		for {
			input, err := stdinReader.ReadString('\n')
			if err != nil {
				consoleLog("Error reading input: %v", err)
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
			consoleLog("Exiting...")
			return
		case input, ok := <-inputChan:
			if !ok {
				consoleLog("Input channel closed.")
				return
			}

			// Parse user input
			parts := strings.Fields(input)
			if len(parts) == 0 {
				printPrompt()
				continue
			}

			switch parts[0] {
			case "SEND":
				if len(parts) < 3 {
					consoleLog("Invalid SEND command. Use: SEND <RecipientID|ALL> <Message>")
					printPrompt()
					continue
				}
				recipientID := parts[1]
				messageText := strings.Join(parts[2:], " ")

				if recipientID == "ALL" {
					// Encrypt the message using AES with the shared secret
					encryptedData, err := encryptAES(hashedSecret, []byte(messageText))
					if err != nil {
						consoleLog("Error encrypting message: %v", err)
						printPrompt()
						continue
					}
					// Encode the encrypted data in hex
					encryptedDataHex := hex.EncodeToString(encryptedData)
					// Send the encrypted message to the server
					fmt.Fprintf(conn, "SEND ALL %s\n", encryptedDataHex)
				} else {
					// Generate a one-time pad (OTP) key
					key := make([]byte, len(messageText))
					_, err := rand.Read(key)
					if err != nil {
						consoleLog("Error generating OTP key: %v", err)
						printPrompt()
						continue
					}

					// Encrypt the message using XOR cipher
					plaintext := []byte(messageText)
					ciphertext := encryptXOR(plaintext, key)

					// Encode key and ciphertext in hex
					keyHex := hex.EncodeToString(key)
					ciphertextHex := hex.EncodeToString(ciphertext)

					// Send the encrypted message in the format: SEND <RecipientID> <key_hex>|<ciphertext_hex>
					encryptedData := keyHex + "|" + ciphertextHex
					fmt.Fprintf(conn, "SEND %s %s\n", recipientID, encryptedData)
				}
				printPrompt()
			case "HELP":
				// Display client commands help
				printUsage(false)
				printPrompt()
			case "EXIT":
				// Exit the client program
				fmt.Fprintf(conn, "EXIT\n")
				consoleLog("Exiting...")
				return
			default:
				// Pass other commands to the server
				fmt.Fprintf(conn, "%s\n", input)
			}
		}
	}
}
