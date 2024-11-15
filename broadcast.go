// broadcast.go
// Package main handles broadcasting messages to all connected clients.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

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
