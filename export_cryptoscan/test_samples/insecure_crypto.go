package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"time"
)

// Example of insecure cryptographic implementations
// DO NOT use these in production!

func main() {
	// Example 1: Using weak hash algorithm (MD5)
	data := []byte("this is a test")
	hash := md5.Sum(data)
	fmt.Printf("MD5 hash: %x\n", hash)

	// Example 2: Using weak hash algorithm (SHA1)
	sha1Hash := sha1.Sum(data)
	fmt.Printf("SHA1 hash: %x\n", sha1Hash)

	// Example 3: Insecure random number generation
	rand.Seed(time.Now().UnixNano())
	randomValue := rand.Intn(100)
	fmt.Printf("Random value: %d\n", randomValue)

	// Example 4: Using DES encryption (weak algorithm)
	key := []byte("8bytekey") // DES uses 8-byte keys (weak)
	block, _ := des.NewCipher(key)
	
	// Static IV (instead of random)
	iv := []byte("staticiv")
	
	// Plaintext should be a multiple of the block size
	plaintext := []byte("This is a secret message that needs protection")
	
	// Make sure plaintext is a multiple of the block size
	padding := block.BlockSize() - (len(plaintext) % block.BlockSize())
	paddedPlaintext := append(plaintext, make([]byte, padding)...)
	
	// Create ciphertext buffer
	ciphertext := make([]byte, len(paddedPlaintext))
	
	// Use ECB mode manually (insecure)
	for i := 0; i < len(paddedPlaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], paddedPlaintext[i:i+block.BlockSize()])
	}
	
	fmt.Printf("DES encrypted (ECB mode): %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	// Example 5: Using RC4 (broken stream cipher)
	rc4Key := []byte("rc4insecurekey")
	rc4Cipher, _ := rc4.NewCipher(rc4Key)
	rc4Result := make([]byte, len(plaintext))
	rc4Cipher.XORKeyStream(rc4Result, plaintext)
	
	fmt.Printf("RC4 encrypted: %s\n", base64.StdEncoding.EncodeToString(rc4Result))

	// Example 6: Hardcoded credentials in source code
	apiKey := "AIzaSyA1_ECqZEFYtOv5RAZaSIrnT1JO3JWzMjM"
	authToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Q6CM1qIQkICX3JwOp28MtlTIFv0IAT61nSLYyLXbG0A"
	
	fmt.Printf("Using API key: %s\n", maskString(apiKey))
	fmt.Printf("Using auth token: %s\n", maskString(authToken))
}

// Helper function to mask sensitive data in output
func maskString(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "..." + s[len(s)-4:]
}