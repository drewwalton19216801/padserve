// operator.go
// Package main handles operator-related commands and functions, including operator commands such as KICK, BAN, UNBAN, and LISTBANS.

package main

import (
	"fmt"
	"net"
	"sync"
)

var (
	operatorID    string           // operatorID stores the client ID of the operator.
	operatorMutex = sync.RWMutex{} // operatorMutex synchronizes access to the operatorID variable.
)

// isOperator returns true if the provided client ID is the operator's ID.
func isOperator(clientID string) bool {
	operatorMutex.RLock()
	defer operatorMutex.RUnlock()
	return clientID == operatorID
}

// handleOperatorCommand processes operator commands issued by the operator client.
// Supported commands include:
// - KICK <clientID>: Disconnects the specified client from the server.
// - BAN <clientID>: Bans the specified client and disconnects them if connected.
// - UNBAN <clientID>: Removes a client from the banned list.
// - LISTBANS: Lists all currently banned clients.
// The function checks if the sender is the operator before executing the command.
func handleOperatorCommand(command, senderID string, args []string, conn net.Conn) {
	if !isOperator(senderID) {
		conn.Write([]byte("ERROR Not authorized as operator\n"))
		return
	}

	switch command {
	case "KICK":
		if len(args) != 1 {
			conn.Write([]byte("ERROR Usage: KICK <clientID>\n"))
			return
		}
		targetID := args[0]

		// Don't allow kicking the operator
		if targetID == operatorID {
			conn.Write([]byte("ERROR Cannot kick the operator\n"))
			return
		}

		// Lock the clients map to safely access and modify it
		clientMutex.Lock()
		if client, exists := clients[targetID]; exists {
			client.Conn.Write([]byte("KICKED You have been kicked by the operator\n"))
			client.Conn.Close()
			delete(clients, targetID)
			conn.Write([]byte(fmt.Sprintf("SUCCESS Kicked client %s\n", targetID)))
		} else {
			conn.Write([]byte(fmt.Sprintf("ERROR Client %s not found\n", targetID)))
		}
		clientMutex.Unlock()
	case "BAN":
		if len(args) != 1 {
			conn.Write([]byte("ERROR Usage: BAN <clientID>\n"))
			return
		}
		targetID := args[0]
		if targetID == operatorID {
			conn.Write([]byte("ERROR Cannot ban the operator\n"))
			return
		}
		// Add client to the banned list
		banMutex.Lock()
		bannedClients[targetID] = true
		banMutex.Unlock()
		// Disconnect the client if connected
		clientMutex.Lock()
		if client, exists := clients[targetID]; exists {
			client.Conn.Write([]byte("BANNED You have been banned by the operator\n"))
			client.Conn.Close()
			delete(clients, targetID)
		}
		clientMutex.Unlock()
		conn.Write([]byte(fmt.Sprintf("SUCCESS Banned client %s\n", targetID)))
	case "UNBAN":
		if len(args) != 1 {
			conn.Write([]byte("ERROR Usage: UNBAN <clientID>\n"))
			return
		}
		targetID := args[0]
		// Remove client from the banned list
		banMutex.Lock()
		if _, exists := bannedClients[targetID]; exists {
			delete(bannedClients, targetID)
			conn.Write([]byte(fmt.Sprintf("SUCCESS Unbanned client %s\n", targetID)))
		} else {
			conn.Write([]byte(fmt.Sprintf("ERROR Client %s not found in banned list\n", targetID)))
		}
		banMutex.Unlock()
	case "LISTBANS":
		// List all banned clients
		conn.Write([]byte("BEGIN_RESPONSE\n"))
		banMutex.RLock()
		if len(bannedClients) == 0 {
			conn.Write([]byte("No clients are currently banned\n"))
		} else {
			for clientID := range bannedClients {
				conn.Write([]byte(fmt.Sprintf("BANNED %s\n", clientID)))
			}
		}
		banMutex.RUnlock()
		conn.Write([]byte("END_RESPONSE\n"))
	default:
		conn.Write([]byte("ERROR Unknown operator command\n"))
	}
}
