// client.go
// Package main handles client setup and connection functions, including key exchange and registration.

package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// setupClient initializes the client, registers it with the server, and performs key exchange.
func setupClient(conn net.Conn, clientID string) ([]byte, error) {
	// Generate ECDH key pair for key exchange
	clientPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating ECDH key: %v", err)
	}
	clientPubKey := clientPrivKey.PublicKey()

	// Register with the server
	fmt.Fprintf(conn, "REGISTER %s\n", clientID)

	// Read server response and public key
	reader := bufio.NewReader(conn)

	// Wait for "REGISTERED" response
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("error reading server response: %v", err)
	}
	response = strings.TrimSpace(response)
	if response == "REGISTERED as operator" {
		isOperator = true // Set the global variable
		consoleLog("You are registered as the server operator.")
	} else if response != "REGISTERED" {
		return nil, fmt.Errorf("failed to register with server: %s", response)
	}

	// Read the server's public key
	pubKeyHex := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("error reading public key from server: %v", err)
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
		return nil, fmt.Errorf("error decoding server's public key: %v", err)
	}
	serverPubKey, err := ecdh.P256().NewPublicKey(serverPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating server's public key: %v", err)
	}

	// Compute shared secret using ECDH
	sharedSecret, err := clientPrivKey.ECDH(serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("error computing shared secret: %v", err)
	}
	// Hash the shared secret to derive a symmetric key
	hashedSecret := sha256.Sum256(sharedSecret)

	// Send the client's public key to the server
	clientPubKeyBytes := clientPubKey.Bytes()
	fmt.Fprintf(conn, "CLIENTPUBKEY\n")
	fmt.Fprintf(conn, "%s\n", hex.EncodeToString(clientPubKeyBytes))
	fmt.Fprintf(conn, "END CLIENTPUBKEY\n")

	// Wait for confirmation from the server
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("error reading server response: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "CLIENTPUBKEY_RECEIVED" {
			break
		} else {
			// Unexpected response from the server
			return nil, fmt.Errorf("unexpected server response: %s", line)
		}
	}

	return hashedSecret[:], nil
}
