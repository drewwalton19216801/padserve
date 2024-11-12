// utils.go
// Package main provides utility functions and variables, including console logging and prompt display.

package main

import (
	"fmt"
	"sync"
)

var (
	consoleMutex sync.Mutex // Mutex for console output synchronization
)

// consoleLog prints messages to the console while maintaining thread safety.
// It ensures that console output from different goroutines does not interleave.
func consoleLog(message string, args ...interface{}) {
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Printf(message+"\n", args...)
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

// printPrompt prints the prompt showing client ID and operator status.
func printPrompt() {
	fmt.Printf("\r%s%s > ", clientID, func() string {
		if isOperator {
			return " (op)"
		}
		return ""
	}())
}
