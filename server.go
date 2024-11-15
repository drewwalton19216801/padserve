// server.go
// Package main implements server-related functions and variables, including the TCP listeners.

package main

import (
	"context"
	"fmt"
	"net"
)

// startListener starts a TCP listener on the specified network and address.
// It accepts incoming connections and spawns a goroutine to handle each client.
func startListener(ctx context.Context, network, address string) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("Server is listening on %s (%s)...\n", address, network)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				fmt.Printf("Error accepting %s connection: %v\n", network, err)
				continue
			}
		}

		// Create a child context for the client
		clientCtx, clientCancel := context.WithCancel(ctx)

		go handleClient(clientCtx, clientCancel, conn)
	}
}
