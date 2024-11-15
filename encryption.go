// encryption.go
// Package main handles encryption and decryption functions, including ECDH key exchange and AES encryption.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// decryptAES decrypts the given ciphertext using AES-CBC mode with the provided key.
// It assumes the ciphertext includes the initialization vector (IV) prepended to the encrypted data.
// It also removes padding added during encryption to ensure the message length is a multiple of the block size.
func decryptAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	// Remove padding added during encryption
	padLen := int(decrypted[len(decrypted)-1])
	if padLen > len(decrypted) {
		return nil, fmt.Errorf("invalid padding")
	}
	return decrypted[:len(decrypted)-padLen], nil
}

// encrypt performs a simple XOR encryption of the message using the provided key.
// It assumes that the key and message are of the same length.
func encrypt(message, key []byte) []byte {
	ciphertext := make([]byte, len(message))
	for i := range message {
		ciphertext[i] = message[i] ^ key[i]
	}
	return ciphertext
}
