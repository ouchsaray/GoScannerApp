package main

import (
        "crypto/aes"
        "crypto/cipher"
        "crypto/sha256"
        "encoding/base64"
        "fmt"
)

// This file contains examples of LOW severity cryptographic issues
// They're not critical security problems but could be improved

func main() {
        // Example 1: Using SHA256 for password hashing (acceptable but not ideal)
        // LOW risk: SHA256 is acceptable for most uses but not ideal for password hashing
        password := []byte("user_password")
        hash := sha256.Sum256(password)
        fmt.Printf("SHA256 hash: %x\n", hash)
        
        // Example 2: Using AES-128 (acceptable but not as strong as AES-256)
        // LOW risk: AES-128 is acceptable but AES-256 is preferred for long-term security
        key := make([]byte, 16) // 128 bits
        plaintext := []byte("this is a test message")
        
        block, _ := aes.NewCipher(key)
        ciphertext := make([]byte, len(plaintext))
        
        // Example 3: Using CBC mode without HMAC
        // LOW risk: CBC mode is acceptable but modern AEAD modes preferred
        iv := make([]byte, aes.BlockSize)
        mode := cipher.NewCBCEncrypter(block, iv)
        mode.CryptBlocks(ciphertext, plaintext)
        
        fmt.Printf("AES-128-CBC encrypted: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
        
        // Example 4: Using PBKDF2 with fewer iterations than recommended
        // LOW risk: PBKDF2 < 10000 iteration comments
        fmt.Println("Using PBKDF2 with 5000 iterations for key derivation")
        
        // Example 5: Using RSA-2048 (acceptable but not future-proof)
        // LOW risk: RSA-2048 is acceptable but consider upgrading to 4096 bits for future-proofing
        fmt.Println("Using RSA-2048 for encryption")
        
        // Example 6: Plaintext password reference
        // LOW risk: Password reference found
        userPassword := "plaintext password here"
        fmt.Println("Password length:", len(userPassword))
        
        // Example 7: Security TODO comment
        // LOW risk: Security-related TODO comment
        fmt.Println("TODO: security - implement proper key management")
        
        // Example 8: Crypto FIXME comment
        // LOW risk: Cryptography-related FIXME comment
        fmt.Println("FIXME: crypto - use a secure password hashing method")
        
        // Example 9: Public key in source code
        publicKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Tz2mr7SZiAMfQyuvBjM
9OiJjRazXBZ1BjP5CE/Wm/Rr500PRK+Lh9x5eJPo5CAZ3/ANBE0sTK0ZsDGMak2m
1g7LSFwiz8ck/1TWB5K/6NxqDOdulM25DPlNUzkHGOqEavCC6b4QcjJ3dq+EPJFC
mzC8MPdkRg5x67+eOAklXEzenyLU5FWJzfhMXVu1K9UXXoV/9ZhBqN7Ve1jJ9H4Z
LOrA/n27NnmYLYWkHTMHs4k/fQK7wseA4wwYsWRRR14wbo+XxFzWtCJ1Xmx/pyRS
kgyOcbvP0Jh/8SnENXUtX8dBKrUx8HQPscYxG+QIWZm0TfM3eKDxMDXyMj4QfLT3
NQIDAQAB
-----END PUBLIC KEY-----`
        fmt.Println("Using public key:", publicKeyPEM[:30]+"...")
        
        // Example 10: Plaintext data reference
        // LOW risk: Plaintext data reference 
        sensitiveData := "plaintext credit card number"
        fmt.Println("Storing plaintext data in database:", sensitiveData)
}