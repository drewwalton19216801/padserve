# Padserve - Secure Messaging System over Tailscale

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Go](https://github.com/drewwalton19216801/padserve/actions/workflows/go.yml/badge.svg)](https://github.com/drewwalton19216801/padserve/actions/workflows/go.yml)

This Go-based messaging system implements a secure TCP server-client communication protocol, utilizing Tailscale to establish a secure network overlay. The server and clients use elliptic curve Diffie-Hellman (ECDH) key exchange to establish a shared secret for encrypted message exchanges, providing secure, authenticated communication over the Tailscale network.

## Features

1. **ECDH Key Exchange:** The server and client exchange public keys to establish a shared secret.
2. **AES and OTP Encryption:** Messages are encrypted using AES for all-client messages or OTP for one-to-one messages.
3. **Tailscale Integration:** This system is designed to work exclusively over Tailscale, using its internal IP addresses (100.64.0.0/10 and fd7a:115c:a1e0::/48).
4. **IPv4 and IPv6 Support:** The server now supports binding to both IPv4 and IPv6 Tailscale addresses, based on user preferences.
5. **Basic Commands:** Support for user registration, listing active users, sending messages, and fetching server information.
6. **Operator Commands:** Support for basic server operator command including banning and unbanning of clients.

## Requirements

1. [Go](https://golang.org/doc/install) (version 1.23.2 or later)
2. [Tailscale](https://tailscale.com/) installed and running
3. A configured Tailscale network

## Installation

Clone the repository and navigate to the project directory:

```sh
git clone https://github.com/drewwalton19216801/padserve.git
cd padserve
```

## Building the Server

To build the server, run the following command:

```sh
go build
```

## Running the Server

The server can detect its Tailscale IP address (both IPv4 and IPv6) and listen on port `12345`. The server can be run in IPv4 mode, IPv6 mode, or both, based on user preferences.

1. Ensure Tailscale is active and configured.
2. Start the server with:

   ```sh
   go run . [-ipv4] [-ipv6]
   ```
   
   Use the `-ipv4` flag to enable IPv4 mode, the `-ipv6` flag to enable IPv6 mode, or both to enable dual-stack support.

   - If no flags are provided, the server defaults to IPv4 mode.

3. The server will display its Tailscale IP and listen for incoming client connections.

### Server Commands

The server supports the following commands sent from clients:

- `REGISTER <ClientID>`: Registers a new client with a unique ID.
- `SEND <RecipientID|ALL> <Message>`: Sends a message to a specific client or broadcasts to all.
- `LIST`: Lists all connected clients.
- `SERVERHELP`: Lists available server commands.

#### Operator Commands

- `SERVERINFO`: Displays server information.
- `KICK <ClientID>`: Disconnects the specified client from the server.
- `BAN <ClientID>`: Bans the specified client and disconnects them if connected.
- `UNBAN <ClientID>`: Removes a client from the banned list.
- `LISTBANS`: Lists all banned clients.

## Running the Client

**UPDATE:** The client has been moved from this repository to its own repository. Please refer to the [Padserve Client](https://github.com/drewwalton19216801/padclient) for usage instructions.

## Example Usage

1. Start the server:

   ```sh
   go run . -ipv4 -ipv6
   ```
   
   This starts the server in dual-stack mode, listening on both IPv4 and IPv6 addresses.

## Notes

- Ensure that all clients are on the same Tailscale network.
- Each client should register with a unique identifier (the server will reject duplicate identifiers).
- The server supports encrypted messaging; however, it is limited to the Tailscale network.
- Both the client and server are cross-platform and have been tested on macOS, Windows, Linux, and FreeBSD.
- The server can now operate in IPv4, IPv6, or both modes, depending on the specified flags.

## Security Considerations

- Messages are encrypted with either AES (for all-client messages) or OTP encryption (for individual messages).
- Shared secrets are derived using ECDH and hashed with SHA-256.
- Operator commands are restricted to the client initially registered as the operator.

## Contributing

Please refer to our [CONTRIBUTING.md](docs/CONTRIBUTING.md) file for details on how to contribute to this project.

## Also See

- [tailutils](https://github.com/drewwalton19216801/tailutils) for Tailscale utility functions
- [padclient](https://github.com/drewwalton19216801/padclient) for the official Padserve Client implementation

## License

This project is licensed under the MIT license.

