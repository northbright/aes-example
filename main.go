package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {
	text := "Hello World!"
	// Key size: 32 bytes
	key := "12345678901234567890123456789012"
	// iv size: 16 bytes
	iv := "1234567890123456"

	cipher, err := Encrypt([]byte(text), []byte(key), []byte(iv))
	if err != nil {
		fmt.Printf("Encrypt() error: %v", err)
		return
	}

	fmt.Printf("cipher: %s\n", string(cipher))

	// Output:
	// baf8c5e30e4cf72a8862bb91124322fc
}

// PKCS7Padding returns the data with PKCS7 padding appended.
func PKCS7Padding(src []byte, blockSize int) []byte {
	n := blockSize - len(src)%blockSize

	var padding []byte
	for i := 0; i < n; i++ {
		padding = append(padding, byte(n))
	}

	return append(src, padding...)
}

// Encrypt encrypts data using AES-256 with CBC mode and PKCS7 padding.
func Encrypt(data, key, iv []byte) (string, error) {
	// New a cipher block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher() error: %v", err)
	}

	// Get padded text using PKCS7 padding.
	paddedText := PKCS7Padding(data, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))

	// Use CBC mode.
	mode := cipher.NewCBCEncrypter(block, iv)

	//Get cipher.
	mode.CryptBlocks(ciphertext, paddedText)

	return fmt.Sprintf("%x", ciphertext), nil
}
