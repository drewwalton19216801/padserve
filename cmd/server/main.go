// main.go
// Package main initializes the server, parses command-line flags, generates the server's ECDH key pair,
// and starts TCP listeners on the Tailscale IP addresses. It supports IPv4 and/or IPv6 based on the provided flags.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"sync"

	"github.com/drewwalton19216801/tailutils"
)

// serverPrivKey holds the server's ECDH private key.
var serverPrivKey *ecdh.PrivateKey

// serverPubKey holds the server's ECDH public key.
var serverPubKey *ecdh.PublicKey

var listenerWG sync.WaitGroup // listenerWG manages synchronization of listener goroutines.

func main() {
	// Define command-line flags
	var ipv4Flag, ipv6Flag bool
	flag.BoolVar(&ipv4Flag, "ipv4", false, "Enable IPv4 mode")
	flag.BoolVar(&ipv6Flag, "ipv6", false, "Enable IPv6 mode")
	flag.Parse()

	// Create a root context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Determine modes based on flags
	if !ipv4Flag && !ipv6Flag {
		ipv4Flag = true
		fmt.Println("No mode specified, defaulting to IPv4")
	} else {
		if ipv4Flag && ipv6Flag {
			fmt.Println("Running in both IPv4 and IPv6 modes")
		} else if ipv4Flag {
			fmt.Println("Running in IPv4 mode")
		} else if ipv6Flag {
			fmt.Println("Running in IPv6 mode")
		}
	}

	var err error
	// Generate ECDH key pair
	serverPrivKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating ECDH key:", err)
		return
	}
	serverPubKey = serverPrivKey.PublicKey()

	// Initialize WaitGroup
	listenerWG = sync.WaitGroup{}

	// Start listeners based on the selected modes
	if ipv4Flag {
		ip4, err := tailutils.GetTailscaleIP()
		if err != nil {
			fmt.Println("Error getting Tailscale IPv4:", err)
			return
		}
		address4 := ip4 + ":12345" // Use port 12345 (FIXME: make this configurable)
		listenerWG.Add(1)
		go func() {
			defer listenerWG.Done()
			err := startListener(ctx, "tcp4", address4)
			if err != nil {
				fmt.Printf("IPv4 listener error: %v\n", err)
			}
		}()
	}

	if ipv6Flag {
		ip6, err := tailutils.GetTailscaleIP6()
		if err != nil {
			fmt.Println("Error getting Tailscale IPv6:", err)
			return
		}
		// Enclose IPv6 address in brackets
		address6 := fmt.Sprintf("[%s]:12345", ip6)
		listenerWG.Add(1)
		go func() {
			defer listenerWG.Done()
			err := startListener(ctx, "tcp6", address6)
			if err != nil {
				fmt.Printf("IPv6 listener error: %v\n", err)
			}
		}()
	}

	// Wait for all listeners to finish (which is never, unless shutdown)
	listenerWG.Wait()
}
