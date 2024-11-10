// Package main implements a client for a secure TCP server that communicates over a Tailscale network.
// The client registers with the server, performs an ECDH key exchange to establish a shared secret,
// and allows the user to send encrypted messages to other clients or broadcast messages to all clients.
// The client supports commands such as SEND, HELP, SERVERHELP, and EXIT.
//
// Commands:
// - SEND <RecipientID|ALL> <Message>: Sends a message to a specific client or broadcasts to all clients.
//   - If RecipientID is "ALL", the message is broadcast to all clients using AES encryption with the shared secret key established via ECDH.
//   - If RecipientID is a specific client ID, the message is encrypted using a one-time pad (OTP) encryption (XOR cipher).
//     A random key is generated for each message, and both the key and the ciphertext are sent to the server.
//
// - HELP: Displays the list of available client commands.
// - SERVERHELP: Requests and displays the list of available server commands from the server.
// - EXIT: Exits the client program.
//
// Encryption:
// - The client performs an ECDH key exchange with the server to establish a shared secret key.
// - Broadcast messages ("SEND ALL") are encrypted using AES encryption with the shared secret key.
// - Direct messages ("SEND <RecipientID>") are encrypted using a one-time pad (OTP) encryption (XOR cipher).
//
// Notes:
// - The client listens for messages from the server in a separate goroutine and processes them accordingly.
// - Incoming messages are decrypted based on the encryption method used (AES for broadcasts, OTP for direct messages).
// - The client checks for a Tailscale network connection before attempting to connect to the server.
// - The first client to register becomes the server operator and has additional privileges.
// - The client handles disconnection scenarios and cleanly exits when necessary.
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
	"sync"

	"github.com/drewwalton19216801/tailutils"
)

var (
	isOperator   bool       // Flag to track if the client is the operator
	consoleMutex sync.Mutex // Mutex for console output
	clientID     string
)

// encrypt performs OTP encryption (XOR cipher) on the message using the provided key.
func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}

// consoleLog prints messages to the console while maintaining the prompt
func consoleLog(message string, args ...interface{}) {
	consoleMutex.Lock()
	defer consoleMutex.Unlock()

	// Save the cursor position, clear the line, print message, restore cursor, and then reprint the prompt
	fmt.Print("\033[s") // Save cursor position
	fmt.Print("\033[K") // Clear to the end of the line

	// Print the message
	fmt.Printf(message+"\n", args...)

	// Restore cursor position and print the prompt
	fmt.Print("\033[u") // Restore cursor position
}

// readMessages continuously reads messages from the server and processes them.
func readMessages(conn net.Conn, done chan bool) {
	reader := bufio.NewReader(conn)
	var inMultiLineResponse bool = false
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			consoleLog("Disconnected from server.")
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
			consoleLog("\rYou are registered as the server operator.")
			printPrompt()
			continue
		}

		// Handle being kicked
		if message == "KICKED You have been kicked by the operator" {
			consoleLog("\rYou have been kicked from the server by the operator.")
			done <- true
			return
		}

		// Handle being banned
		if message == "BANNED You have been banned by the operator" {
			consoleLog("\rYou have been banned from the server by the operator.")
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
			printPrompt()
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
				consoleLog("\rInvalid message format from %s. Ignoring.\n> ", senderID)
				continue
			}
			keyHex := dataParts[0]
			ciphertextHex := dataParts[1]

			// Decode hex strings
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				consoleLog("\rError decoding key from %s: %v\n> ", senderID, err)
				continue
			}
			ciphertext, err := hex.DecodeString(ciphertextHex)
			if err != nil {
				consoleLog("\rError decoding ciphertext from %s: %v\n> ", senderID, err)
				continue
			}

			// Decrypt the message
			if len(key) != len(ciphertext) {
				consoleLog("\rKey and ciphertext lengths do not match from %s.\n> ", senderID)
				continue
			}
			plaintext := encrypt(ciphertext, key)
			if strings.HasPrefix(senderInfo, "MESSAGE from") {
				consoleLog("\rMessage from %s: %s", senderID, string(plaintext))
			} else if strings.HasPrefix(senderInfo, "BROADCAST from") {
				consoleLog("\rBroadcast from %s: %s", senderID, string(plaintext))
			}

			printPrompt()
		} else {
			consoleLog(message)

			if !inMultiLineResponse {
				printPrompt()
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
		consoleLog("Invalid command.")
		printCommands()
	} else {
		printCommands()
	}
}

// printCommands prints the list of available client and server commands.
func printCommands() {
	consoleLog("Available client commands:")
	consoleLog("SEND <RecipientID|ALL> <Message> - Send a message to a specific client or all clients")
	consoleLog("HELP - Print this help text")
	consoleLog("SERVERHELP - Print server help text")
	consoleLog("EXIT - Exit the program")
}

// printPrompt prints the prompt showing client ID and operator status
func printPrompt() {
	fmt.Printf("\r%s%s > ", clientID, func() string {
		if isOperator {
			return " (op)"
		}
		return ""
	}())
}

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
		consoleLog("Error checking local IP address:", err)
		return
	}
	if !isTailscale {
		consoleLog("Please connect to a Tailscale network.")
		return
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		consoleLog("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	// Generate ECDH key pair
	clientPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		consoleLog("Error generating ECDH key:", err)
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
		consoleLog("Error reading server response:", err)
		return
	}
	response = strings.TrimSpace(response)
	if response == "REGISTERED as operator" {
		isOperator = true
		consoleLog("You are registered as the server operator.")
	} else if response != "REGISTERED" {
		consoleLog("Failed to register with server:", response)
		return
	}

	// Now read the server's public key
	pubKeyHex := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			consoleLog("Error reading public key from server:", err)
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
		consoleLog("Error decoding server's public key:", err)
		return
	}
	serverPubKey, err := ecdh.P256().NewPublicKey(serverPubKeyBytes)
	if err != nil {
		consoleLog("Error creating server's public key:", err)
		return
	}

	// Compute shared secret
	sharedSecret, err := clientPrivKey.ECDH(serverPubKey)
	if err != nil {
		consoleLog("Error computing shared secret:", err)
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
			consoleLog("Error reading server response:", err)
			return
		}
		line = strings.TrimSpace(line)
		if line == "CLIENTPUBKEY_RECEIVED" {
			break
		} else {
			// We got something else, error
			consoleLog("Unexpected server response:", line)
			return
		}
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

	// Start a goroutine to read user input
	inputChan := make(chan string)
	go func() {
		stdinReader := bufio.NewReader(os.Stdin)
		for {
			input, err := stdinReader.ReadString('\n')
			if err != nil {
				consoleLog("Error reading input:", err)
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

			// Update command parsing to enforce exact match
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
					// Encrypt the message using the shared secret
					encryptedData, err := encryptAES(hashedSecret[:], []byte(messageText))
					if err != nil {
						consoleLog("Error encrypting message:", err)
						printPrompt()
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
						consoleLog("Error generating OTP key:", err)
						printPrompt()
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
				printPrompt()
			case "HELP":
				// Handle HELP command
				printUsage(false)
				printPrompt()
			case "EXIT":
				fmt.Fprintf(conn, "EXIT\n")
				consoleLog("Exiting...")
				return
			default:
				// Pass the command to the server
				fmt.Fprintf(conn, "%s\n", input)
			}
		}
	}
}
