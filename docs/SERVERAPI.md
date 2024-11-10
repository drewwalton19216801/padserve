# Secure Messaging Server API Documentation

This document describes the API for interacting with a secure messaging server that uses the Tailscale network. The server provides functionality to manage client registration, key exchange, message encryption, and various server commands.

## Table of Contents
- [Connection](#connection)
- [Client Commands](#client-commands)
  - [REGISTER](#register)
  - [CLIENTPUBKEY](#clientpubkey)
  - [SEND](#send)
  - [LIST](#list)
  - [INFO](#info)
  - [SERVERHELP](#serverhelp)
- [Operator Commands](#operator-commands)
  - [KICK](#kick)
  - [BAN](#ban)
  - [UNBAN](#unban)
  - [LISTBANS](#listbans)
- [Encryption Schemes](#encryption-schemes)

## Connection
The server listens on a secure Tailscale IP address on port `12345`. Clients must connect to the server using the Tailscale network. Ensure you have Tailscale installed and correctly configured to connect.

The server uses ECDH (Elliptic Curve Diffie-Hellman) to establish a shared secret between clients and the server, enabling secure encrypted communication.

## Client Commands

### REGISTER
**Syntax:** `REGISTER <clientID>`

- Registers a client with a unique identifier (`clientID`).
- If successful, the server responds with `REGISTERED`. The first client to register becomes the operator and will receive the message `REGISTERED as operator`.
- Clients will also receive the server's public key to initiate the key exchange.
- **Error Responses:**
  - `ERROR Client name already registered`: The provided client ID is already in use.
  - `ERROR You are banned from this server`: The client is banned.

### CLIENTPUBKEY
**Syntax:** `CLIENTPUBKEY` (followed by the public key data and ending with `END CLIENTPUBKEY`)

- The client sends its public key to the server for key exchange.
- The server calculates a shared secret, which is used for future encrypted communications.

### SEND
**Syntax:** `SEND <recipientID|ALL> <encryptedMessage>`

- Sends an encrypted message to another client or broadcasts it to all connected clients.
- **Parameters:**
  - `recipientID`: The target client for the message. Use `ALL` to broadcast to all clients.
  - `encryptedMessage`: The message encrypted using AES and the shared secret.
- **Error Responses:**
  - `ERROR Shared secret not established`: Shared secret must be established before sending encrypted messages.
  - `ERROR Invalid encrypted data`: The encrypted data could not be processed.

### LIST
**Syntax:** `LIST`

- Lists all connected clients.
- **Response:**
  - `BEGIN_RESPONSE` followed by `CLIENT <clientID>` for each connected client, ending with `END_RESPONSE`.

### INFO
**Syntax:** `INFO`

- Retrieves information about the server, including the Tailscale IP address.
- **Response:**
  - `INFO Tailscale IP(s): <ip-addresses>` or `INFO No Tailscale IP` if unavailable.

### SERVERHELP
**Syntax:** `SERVERHELP`

- Lists available commands that the client can use.
- **Response:**
  - A list of commands, including special operator commands if the client is an operator.

## Operator Commands
The first client to register becomes the operator and has additional privileges.

### KICK
**Syntax:** `KICK <clientID>`

- Disconnects the specified client from the server.
- **Error Responses:**
  - `ERROR Not authorized as operator`: The client is not an operator.
  - `ERROR Cannot kick the operator`: Operators cannot kick themselves.
  - `ERROR Client <clientID> not found`: The specified client does not exist.
  - `SUCCESS Kicked client <clientID>`: The client was successfully removed.

### BAN
**Syntax:** `BAN <clientID>`

- Bans the specified client, preventing them from reconnecting to the server.
- **Error Responses:**
  - `ERROR Not authorized as operator`: The client is not an operator.
  - `ERROR Cannot ban the operator`: Operators cannot ban themselves.
  - `SUCCESS Banned client <clientID>`: The client was successfully banned.

### UNBAN
**Syntax:** `UNBAN <clientID>`

- Removes a ban on a specified client, allowing them to reconnect.
- **Error Responses:**
  - `ERROR Not authorized as operator`: The client is not an operator.
  - `ERROR Client <clientID> not found in banned list`: The client is not currently banned.
  - `SUCCESS Unbanned client <clientID>`: The client was successfully unbanned.

### LISTBANS
**Syntax:** `LISTBANS`

- Lists all currently banned clients.
- **Response:**
  - `BEGIN_RESPONSE` followed by `BANNED <clientID>` for each banned client, ending with `END_RESPONSE`.
  - If no clients are banned, the response will indicate this.

## Encryption Schemes

### Key Exchange (ECDH)
- The server and clients use **Elliptic Curve Diffie-Hellman (ECDH)** to establish a shared secret.
  - **Server Public Key**: After registering, the server sends its public key to the client.
  - **Client Public Key**: The client sends its public key using the `CLIENTPUBKEY` command.
  - **Shared Secret**: The shared secret is calculated from the server's private key and the client's public key. This shared secret is used to derive encryption keys for secure communication.

### Broadcast Messages (AES Encryption)
- **Algorithm**: AES (Advanced Encryption Standard) is used for encrypting messages sent to all clients.
- **Key Derivation**: The shared secret obtained from the ECDH key exchange is hashed using **SHA-256** to derive the AES encryption key.
- **Encryption Mode**: AES is used in **CBC (Cipher Block Chaining)** mode.
  - The **IV (Initialization Vector)** is included at the beginning of the ciphertext.
  - Clients must use the derived shared secret and IV to decrypt the broadcasted message.

### Client-to-Client Messages (OTP Encryption)
- **Algorithm**: One-Time Pad (OTP) is used for direct client-to-client messages.
- **Key Generation**: A random key of the same length as the plaintext message is generated for each recipient.
- **Encryption**:
  - Each byte of the plaintext message is XORed with the corresponding byte of the key to produce the ciphertext.
  - The generated random key is sent along with the encrypted message.
  - **Key and Ciphertext Encoding**: Both the key and ciphertext are encoded in hexadecimal format before transmission.
- **Security Note**: OTP encryption ensures perfect secrecy if the key is truly random and used only once. The recipient uses the provided key to decrypt the message.

## Notes
- The server automatically handles the secure key exchange using ECDH, enabling secure communication.
- Operator commands are restricted to the client initially registered as the operator.
- Use encryption protocols to ensure confidentiality of the messages.

Ensure you understand the secure messaging workflow and respect other users on the server. Proper encryption and following protocol will ensure the safe and effective use of this system.
