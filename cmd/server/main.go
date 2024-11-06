package main

import (
	"bufio"
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
	"net"
	"strings"
	"sync"
)

type Client struct {
	ID           string
	Conn         net.Conn
	PublicKey    *ecdsa.PublicKey
	SharedSecret []byte
}

var (
	clients       = make(map[string]*Client)
	mutex         = &sync.Mutex{}
	serverPrivKey *ecdsa.PrivateKey
	serverPubKey  *ecdsa.PublicKey
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
				pubKeyPEM, err := getPublicKeyPEM()
				if err != nil {
					conn.Write([]byte("ERROR Generating public key\n"))
				} else {
					conn.Write([]byte("PUBLICKEY\n"))
					conn.Write([]byte(pubKeyPEM))
					conn.Write([]byte("END PUBLICKEY\n"))
				}
			} else {
				conn.Write([]byte("ERROR Invalid REGISTER command\n"))
			}
		} else if strings.HasPrefix(message, "CLIENTPUBKEY") {
			// Client is sending its public key
			pubKeyPEM := ""
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
				pubKeyPEM += line + "\n"
			}
			// Parse client's public key
			block, _ := pem.Decode([]byte(pubKeyPEM))
			if block == nil || block.Type != "ECDSA PUBLIC KEY" {
				fmt.Println("Failed to decode client's public key")
				return
			}
			clientPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				fmt.Println("Error parsing client's public key:", err)
				return
			}
			clientECDSAPubKey, ok := clientPubKey.(*ecdsa.PublicKey)
			if !ok {
				fmt.Println("Invalid client's public key type")
				return
			}
			// Compute shared secret
			sharedSecret, err := computeSharedSecret(serverPrivKey, clientECDSAPubKey)
			if err != nil {
				fmt.Println("Error computing shared secret:", err)
				return
			}
			// Store the client's public key and shared secret
			mutex.Lock()
			if client, exists := clients[clientID]; exists {
				client.PublicKey = clientECDSAPubKey
				client.SharedSecret = sharedSecret
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
					// Existing code for sending to a specific client
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
			conn.Write([]byte("ERROR Unknown command\n"))
		}
	}
}

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

func computeSharedSecret(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	x, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	sharedSecret := sha256.Sum256(x.Bytes())
	return sharedSecret[:], nil
}

func getPublicKeyPEM() (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(serverPubKey)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubPEM), nil
}

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

func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}

func printServerCommands() string {
	var helptext string

	helptext += "Available server commands:\n"
	helptext += "LIST - List all connected clients\n"
	helptext += "INFO - Print server information\n"
	helptext += "SERVERHELP - Print this help text\n"

	return helptext
}

func main() {
	var err error
	// Generate ECDSA key pair for ECDH
	serverPrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error generating ECDSA key:", err)
		return
	}
	serverPubKey = &serverPrivKey.PublicKey

	// Inform that we have generated the key
	fmt.Println("Server generated public key:")
	fmt.Println(serverPubKey)

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
