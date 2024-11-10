// Package main implements a client for a secure TCP server that communicates over a Tailscale network.
// The client registers with the server, performs an ECDH key exchange to establish a shared secret,
// and allows the user to send encrypted messages to other clients or broadcast messages to all clients.
//
// Usage:
//
//	go run client.go <YourID> <TailscaleServer>
//
// Replace <YourID> with your chosen client identifier and <TailscaleServer> with the server's
// Tailscale IP address or hostname. Ensure that you are connected to the Tailscale network before running the client.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/drewwalton19216801/tailutils"
)

var isOperator bool

// encrypt performs OTP encryption (XOR cipher) on the message using the provided key.
func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}

// readMessages continuously reads messages from the server and processes them.
func readMessages(conn net.Conn, done chan bool, clientID string) {
	reader := bufio.NewReader(conn)
	var inMultiLineResponse bool = false
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Disconnected from server.")
			done <- true // Signal main function to exit
			return
		}
		message = strings.TrimRight(message, "\r\n")

		if message == "" {
			continue
		}

		// Handle being registered
		if message == "REGISTERED as operator" {
			isOperator = true
			fmt.Println("\rYou are registered as the server operator.")
			printPrompt(clientID, isOperator)
			continue
		}

		// Handle being kicked
		if message == "KICKED You have been kicked by the operator" {
			fmt.Println("\rYou have been kicked from the server by the operator.")
			done <- true
			return
		}

		// Handle being banned
		if message == "BANNED You have been banned by the operator" {
			fmt.Println("\rYou have been banned from the server by the operator.")
			done <- true
			return
		}

		// Detect the start of a multi-line response
		if message == "BEGIN_RESPONSE" {
			inMultiLineResponse = true
			continue // Skip printing the marker
		}

		// Detect the end of a multi-line response
		if message == "END_RESPONSE" {
			inMultiLineResponse = false
			printPrompt(clientID, isOperator)
			continue // Skip printing the marker
		}

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
			fmt.Println(message)

			if !inMultiLineResponse {
				printPrompt(clientID, isOperator)
			}
		}
	}
}

// encryptAES encrypts the plaintext using AES encryption with the provided key.
func encryptAES(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

// printUsage displays help text for the client commands.
func printUsage(invalid bool) {
	if invalid {
		fmt.Println("Invalid command.")
		printCommands()
	} else {
		printCommands()
	}
}

// printCommands prints the list of available client and server commands.
func printCommands() {
	fmt.Println("Available client commands:")
	fmt.Println("SEND <RecipientID|ALL> <Message> - Send a message to a specific client or all clients")
	fmt.Println("HELP - Print this help text")
	fmt.Println("SERVERHELP - Print server help text")
	fmt.Println("EXIT - Exit the program")
}

// printPrompt prints the client prompt, showing the client ID and operator status.
func printPrompt(clientID string, isOperator bool) {
	fmt.Printf("%s%s > ", clientID, func() string {
		if isOperator {
			return " (op)"
		}
		return ""
	}())
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run client.go <YourID> <TailscaleServer>")
		return
	}
	clientID := os.Args[1]
	serverIP := os.Args[2]
	address := serverIP + ":12345"

	// Check if the local IP address belongs to a Tailscale interface
	isTailscale, err := tailutils.HasTailscaleIP()
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

	// Generate ECDH key pair
	clientPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating ECDH key:", err)
		return
	}
	clientPubKey := clientPrivKey.PublicKey()

	// Register with the server
	fmt.Fprintf(conn, "REGISTER %s\n", clientID)

	// Read server response and public key
	reader := bufio.NewReader(conn)

	// Wait for "REGISTERED" response
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading server response:", err)
		return
	}
	response = strings.TrimSpace(response)
	if response == "REGISTERED as operator" {
		isOperator = true
		fmt.Println("You are registered as the server operator.")
	} else if response != "REGISTERED" {
		fmt.Println("Failed to register with server:", response)
		return
	}

	// Now read the server's public key
	pubKeyHex := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading public key from server:", err)
			return
		}
		line = strings.TrimSpace(line)
		if line == "END PUBLICKEY" {
			break
		}
		if line == "PUBLICKEY" {
			continue
		}
		pubKeyHex = line
	}

	// Parse the server's public key
	serverPubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		fmt.Println("Error decoding server's public key:", err)
		return
	}
	serverPubKey, err := ecdh.P256().NewPublicKey(serverPubKeyBytes)
	if err != nil {
		fmt.Println("Error creating server's public key:", err)
		return
	}

	// Compute shared secret
	sharedSecret, err := clientPrivKey.ECDH(serverPubKey)
	if err != nil {
		fmt.Println("Error computing shared secret:", err)
		return
	}
	// Hash the shared secret to derive a key
	hashedSecret := sha256.Sum256(sharedSecret)

	// Send the client's public key to the server
	clientPubKeyBytes := clientPubKey.Bytes()
	fmt.Fprintf(conn, "CLIENTPUBKEY\n")
	fmt.Fprintf(conn, "%s\n", hex.EncodeToString(clientPubKeyBytes))
	fmt.Fprintf(conn, "END CLIENTPUBKEY\n")

	// Wait until we get CLIENTPUBKEY_RECEIVED from the server, error if we don't
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading server response:", err)
			return
		}
		line = strings.TrimSpace(line)
		if line == "CLIENTPUBKEY_RECEIVED" {
			break
		} else {
			// We got something else, error
			fmt.Println("Unexpected server response:", line)
		}
	}

	fmt.Println("Connected to the server. Type your commands below:")
	if isOperator {
		fmt.Println("You are the server operator. Type HELP to see available commands.")
	} else {
		fmt.Println("Type HELP to see available commands.")
	}
	printPrompt(clientID, isOperator)

	// Channel to signal when to exit
	done := make(chan bool)

	// Start a goroutine to read messages from the server
	go readMessages(conn, done, clientID)

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

			// Update command parsing to enforce exact match
			parts := strings.Fields(input)
			if len(parts) == 0 {
				printPrompt(clientID, isOperator)
				continue
			}

			switch parts[0] {
			case "SEND":
				if len(parts) < 3 {
					fmt.Println("Invalid SEND command. Use: SEND <RecipientID|ALL> <Message>")
					printPrompt(clientID, isOperator)
					continue
				}
				recipientID := parts[1]
				messageText := strings.Join(parts[2:], " ")

				if recipientID == "ALL" {
					// Encrypt the message using the shared secret
					encryptedData, err := encryptAES(hashedSecret[:], []byte(messageText))
					if err != nil {
						fmt.Println("Error encrypting message:", err)
						printPrompt(clientID, isOperator)
						continue
					}
					// Encode the encrypted data in hex
					encryptedDataHex := hex.EncodeToString(encryptedData)
					// Send the encrypted message to the server
					fmt.Fprintf(conn, "SEND ALL %s\n", encryptedDataHex)
				} else {
					// Generate OTP key
					key := make([]byte, len(messageText))
					_, err := rand.Read(key)
					if err != nil {
						fmt.Println("Error generating OTP key:", err)
						printPrompt(clientID, isOperator)
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
				printPrompt(clientID, isOperator)
			case "HELP":
				// Handle HELP command
				printUsage(false)
				printPrompt(clientID, isOperator)
			case "EXIT":
				fmt.Fprintf(conn, "EXIT\n")
				fmt.Println("Exiting...")
				return
			default:
				// Pass the command to the server
				fmt.Fprintf(conn, "%s\n", input)
			}
		}
	}
}
