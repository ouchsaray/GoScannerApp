package main

import (
	"crypto/sha256"
	"fmt"
)

// This file contains ONLY LOW severity examples
// to test our LOW severity detection

func main() {
	// LOW severity: SHA256 for general hashing (not passwords)
	// SHA256 is acceptable for most uses but not ideal for password hashing
	data := []byte("general data")
	hash := sha256.Sum256(data)
	fmt.Printf("SHA256 hash: %x\n", hash)
	
	// LOW severity: Password reference
	password := "user_password"
	fmt.Println("Password length:", len(password))
	
	// LOW severity: Security TODO
	fmt.Println("TODO: security - implement proper key management")
	
	// LOW severity: Public key
	fmt.Println(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vS5EwjrYYglfqUF6f0yV0fingerY
UecurlyUf4ebzCYy7nPy+JLxzDiOHcW48yqEobD5UF7umsxGR1qKYCrgCQ==
-----END PUBLIC KEY-----`)
	
	// LOW severity: FIXME crypto
	fmt.Println("FIXME: crypto - use a secure password hashing method")
	
	// LOW severity: Plaintext reference
	fmt.Println("plaintext credentials need to be encrypted")
	
	// LOW severity: Using RSA-2048
	fmt.Println("RSA-2048 is acceptable but consider upgrading to 4096 bits")
	
	// LOW severity: CBC without auth
	fmt.Println("Using CBC mode without authentication")
	
	// LOW severity: PBKDF2 with few iterations
	fmt.Println("PBKDF2 < 10000 iterations for password hashing")
	
	// LOW severity: AES-128
	fmt.Println("AES-128 is acceptable but AES-256 is preferred")
}