# Padserve - Secure Messaging System over Tailscale

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

## Running the Server

The server can detect its Tailscale IP address (both IPv4 and IPv6) and listen on port `12345`. The server can be run in IPv4 mode, IPv6 mode, or both, based on user preferences.

1. Ensure Tailscale is active and configured.
2. Start the server with:

   ```sh
   go run ./cmd/server [-ipv4] [-ipv6]
   ```
   
   Use the `-ipv4` flag to enable IPv4 mode, the `-ipv6` flag to enable IPv6 mode, or both to enable dual-stack support.

   - If no flags are provided, the server defaults to IPv4 mode.

3. The server will display its Tailscale IP and listen for incoming client connections.

### Server Commands

The server supports the following commands sent from clients:

- `REGISTER <ClientID>`: Registers a new client with a unique ID.
- `SEND <RecipientID|ALL> <Message>`: Sends a message to a specific client or broadcasts to all.
- `LIST`: Lists all connected clients.
- `INFO`: Displays server IP and client details.
- `SERVERHELP`: Lists available server commands.

## Running the Client

1. Connect to the Tailscale network and obtain the server’s Tailscale IP.
2. Run the client in another terminal with:

   ```sh
   go run ./cmd/client <YourID> <TailscaleServerAddress>
   ```
   
   Replace `<YourID>` with your chosen identifier and `<TailscaleServerAddress>` with the server's IP or hostname on the Tailscale network.

### Client Commands

Once connected, the client can use these commands:

- `SEND <RecipientID|ALL> <Message>`: Send an encrypted message to a specific client or all clients.
- `LIST`: List all clients connected to the server.
- `HELP`: Display available client commands.
- `SERVERHELP`: Display server help text.
- `EXIT`: Disconnect from the server and exit the client.

### Operator Commands

The first client to connect to the server is given access to Operator commands:

- `KICK <ClientID>`: Kick the specified client from the server.
- `BAN <ClientID>`: Ban the specified client from the server.
- `UNBAN <ClientID>`: Unban the specified client from the server.
- `LISTBANS`: List the currently banned clients on the server.

## Example Usage

1. Start the server:

   ```sh
   go run ./cmd/server -ipv4 -ipv6
   ```
   
   This starts the server in dual-stack mode, listening on both IPv4 and IPv6 addresses.

2. Start at least two clients:

   ```sh
   go run ./cmd/client Someone 100.64.x.x
   ```
   
   Replace `Someone` with the client's chosen ID and `100.64.x.x` with the server's Tailscale IP address or hostname.

3. List connected clients:

   ```
   LIST
   ```

4. Send a direct message:

   ```
   SEND Bob Hello, Bob!
   ```
   
   Replace `Bob` with the client ID of another client.

5. Send a broadcast message:

   ```
   SEND ALL Hello, everyone!
   ```

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

## License

This project is licensed under the MIT license.

