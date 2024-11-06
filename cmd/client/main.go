package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// isTailscale checks if the local machine has an IP address within the Tailscale network (100.64.0.0/10).
func isTailscale() (bool, error) {
	// Define the Tailscale IP range
	_, tsNet, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return false, fmt.Errorf("failed to parse Tailscale CIDR: %v", err)
	}

	// Get a list of all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("failed to get network interfaces: %v", err)
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

			// Skip loopback and link-local addresses
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			// Check if the IP is within the Tailscale network
			if tsNet.Contains(ip) {
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

	// Generate ECDSA key pair for ECDH
	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error generating ECDSA key:", err)
		return
	}
	clientPubKey := &clientPrivKey.PublicKey

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
	if response != "REGISTERED" {
		fmt.Println("Failed to register with server:", response)
		return
	}

	// Now read the server's public key
	pubKeyPEM := ""
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
		pubKeyPEM += line + "\n"
	}

	// Parse the server's public key
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "ECDSA PUBLIC KEY" {
		fmt.Println("Failed to decode server's public key")
		return
	}
	serverPubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing server's public key:", err)
		return
	}
	serverPubKey, ok := serverPubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Invalid server public key type")
		return
	}

	// Compute shared secret
	sharedSecret, err := computeSharedSecret(clientPrivKey, serverPubKey)
	if err != nil {
		fmt.Println("Error computing shared secret:", err)
		return
	}

	// Send the client's public key to the server
	clientPubKeyPEM, err := getPublicKeyPEM(clientPubKey)
	if err != nil {
		fmt.Println("Error encoding client's public key:", err)
		return
	}
	fmt.Fprintf(conn, "CLIENTPUBKEY\n")
	fmt.Fprintf(conn, "%s", clientPubKeyPEM)
	fmt.Fprintf(conn, "END CLIENTPUBKEY\n")

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
					// Encrypt the message using the shared secret
					encryptedData, err := encryptAES(sharedSecret, []byte(messageText))
					if err != nil {
						fmt.Println("Error encrypting message:", err)
						fmt.Print("> ")
						continue
					}
					// Encode the encrypted data in hex
					encryptedDataHex := hex.EncodeToString(encryptedData)
					// Send the encrypted message to the server
					fmt.Fprintf(conn, "SEND ALL %s\n", encryptedDataHex)
				} else {
					// ... [Existing code for sending to a specific client] ...
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
			} else if strings.HasPrefix(input, "EXIT") || strings.HasPrefix(input, "exit") {
				fmt.Fprintf(conn, "EXIT\n")
				fmt.Println("Exiting...")
				return
			} else {
				// Send the command to the server
				fmt.Fprintf(conn, "%s\n", input)
			}
			fmt.Print("> ")
		}
	}
}

func computeSharedSecret(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	x, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	sharedSecret := sha256.Sum256(x.Bytes())
	return sharedSecret[:], nil
}

func getPublicKeyPEM(pubKey *ecdsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubPEM), nil
}

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

// Help text for the client
func printUsage(invalid bool) {
	if invalid {
		fmt.Println("Invalid command.")
		printCommands()
	} else {
		printCommands()
	}
}

func printCommands() {
	fmt.Println("Available client commands:")
	fmt.Println("SEND <RecipientID|ALL> <Message> - Send a message to a specific client or all clients")
	fmt.Println("HELP - Print this help text")
	fmt.Println("EXIT - Exit the program")
	fmt.Println()
	fmt.Println("Available server commands:")
	fmt.Println("INFO - Print server information")
}
