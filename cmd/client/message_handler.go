// message_handler.go
// Package main handles reading and processing messages from the server.

package main

import (
	"bufio"
	"encoding/hex"
	"net"
	"strings"
)

// readMessages continuously reads messages from the server and processes them.
// It handles different types of messages such as regular messages, broadcasts,
// multi-line responses, and disconnection notices.
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

		// Handle being registered as operator
		if message == "REGISTERED as operator" {
			isOperator = true
			consoleLog("You are registered as the server operator.")
			printPrompt()
			continue
		}

		// Handle being kicked
		if message == "KICKED You have been kicked by the operator" {
			consoleLog("You have been kicked from the server by the operator.")
			done <- true
			return
		}

		// Handle being banned
		if message == "BANNED You have been banned by the operator" {
			consoleLog("You have been banned from the server by the operator.")
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

		// Handle incoming messages from other clients
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
				consoleLog("Invalid message format from %s. Ignoring.", senderID)
				continue
			}
			keyHex := dataParts[0]
			ciphertextHex := dataParts[1]

			// Decode hex strings
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				consoleLog("Error decoding key from %s: %v", senderID, err)
				continue
			}
			ciphertext, err := hex.DecodeString(ciphertextHex)
			if err != nil {
				consoleLog("Error decoding ciphertext from %s: %v", senderID, err)
				continue
			}

			// Decrypt the message using XOR cipher
			if len(key) != len(ciphertext) {
				consoleLog("Key and ciphertext lengths do not match from %s.", senderID)
				continue
			}
			plaintext := encryptXOR(ciphertext, key)
			if strings.HasPrefix(senderInfo, "MESSAGE from") {
				consoleLog("Message from %s: %s", senderID, string(plaintext))
			} else if strings.HasPrefix(senderInfo, "BROADCAST from") {
				consoleLog("Broadcast from %s: %s", senderID, string(plaintext))
			}

			printPrompt()
		} else {
			// Handle other server messages
			consoleLog(message)
			if !inMultiLineResponse {
				printPrompt()
			}
		}
	}
}
