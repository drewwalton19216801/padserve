// utils.go
// Package main provides utility functions and variables, including banned clients management and server command listings.

package main

import (
	"sync"
)

var (
	bannedClients = make(map[string]bool) // bannedClients maps banned client IDs to a boolean value.
	banMutex      = sync.RWMutex{}        // banMutex synchronizes access to the bannedClients map.
)

// isBanned returns true if the provided client ID is banned.
func isBanned(clientID string) bool {
	banMutex.RLock()
	defer banMutex.RUnlock()
	return bannedClients[clientID]
}

// printServerCommands returns a string containing the list of available server commands.
// If the client is the operator, it includes operator-specific commands.
func printServerCommands(isOperator bool) string {
	var helptext string

	helptext += "Available server commands:\n"
	helptext += "LIST - List all connected clients\n"
	helptext += "INFO - Print server information\n"

	if isOperator {
		helptext += "Operator commands:\n"
		helptext += "KICK <clientID> - Kick a client from the server\n"
		helptext += "BAN <clientID> - Ban a client from the server\n"
		helptext += "UNBAN <clientID> - Unban a client from the server\n"
		helptext += "LISTBANS - List all banned clients\n"
	}

	helptext += "END SERVERHELP\n"

	return helptext
}
