package scanner

import (
        "bytes"
        "encoding/base64"
        "path/filepath"
        "regexp"

        "github.com/yourusername/cryptoscan/pkg/types"
)

// Detector is responsible for detecting cryptographic assets
type Detector struct {
        patterns map[string]*regexp.Regexp
}

// NewDetector creates a new detector
func NewDetector() *Detector {
        return &Detector{
                patterns: map[string]*regexp.Regexp{
                        // Private key formats
                        "RSA Private Key":       regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----(.|\s)*?-----END RSA PRIVATE KEY-----`),
                        "Private Key":           regexp.MustCompile(`-----BEGIN PRIVATE KEY-----(.|\s)*?-----END PRIVATE KEY-----`),
                        "OpenSSH Private Key":   regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----(.|\s)*?-----END OPENSSH PRIVATE KEY-----`),
                        "EC Private Key":        regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----(.|\s)*?-----END EC PRIVATE KEY-----`),
                        "DSA Private Key":       regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----(.|\s)*?-----END DSA PRIVATE KEY-----`),
                        
                        // Public certificates and keys
                        "Certificate":           regexp.MustCompile(`-----BEGIN CERTIFICATE-----(.|\s)*?-----END CERTIFICATE-----`),
                        "Public Key":            regexp.MustCompile(`-----BEGIN PUBLIC KEY-----(.|\s)*?-----END PUBLIC KEY-----`),
                        "RSA Public Key":        regexp.MustCompile(`-----BEGIN RSA PUBLIC KEY-----(.|\s)*?-----END RSA PUBLIC KEY-----`),
                        "SSH Public Key":        regexp.MustCompile(`ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}( .*)?`),
                        
                        // PGP keys
                        "PGP Private Key Block": regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----(.|\s)*?-----END PGP PRIVATE KEY BLOCK-----`),
                        "PGP Public Key Block":  regexp.MustCompile(`-----BEGIN PGP PUBLIC KEY BLOCK-----(.|\s)*?-----END PGP PUBLIC KEY BLOCK-----`),
                        
                        // Various service-specific API tokens and keys
                        "AWS Access Key":        regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
                        "AWS Secret Key":        regexp.MustCompile(`(?i)aws(.{0,20})?(?:secret|key)(.{0,20})?[=:]\s*['"]([\w/+]{40})['"]\s*`),
                        "Google API Key":        regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
                        "Google OAuth ID":       regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
                        "Google OAuth Secret":   regexp.MustCompile(`[a-zA-Z0-9-_]{24}`),
                        "Stripe API Key":        regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
                        "Stripe Publishable Key": regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`),
                        
                        // Authentication tokens
                        "JWT Token":             regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
                        "GitHub Token":          regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
                        "GitHub OAuth":          regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
                        
                        // Named keys/credentials in code
                        "Base64 Key":            regexp.MustCompile(`(?i)(key|token|secret|password|credential)([a-zA-Z0-9_\-]*)(:|=|:=|\s+:=\s+)(\s*['"]?)([A-Za-z0-9+/]{40,}=*)(['"]?)`),
                        
                        // LOW severity patterns
                        "Security TODO Comment":  regexp.MustCompile(`TODO: security`),
                        "Crypto FIXME Comment":   regexp.MustCompile(`FIXME: crypto`),
                        "Password Reference":     regexp.MustCompile(`(?i)(password|passwd)(\s*=\s*|\s*:=\s*|\s*:\s*)(['"])([^'"]{3,})(['"])`),
                        "Plaintext Reference":    regexp.MustCompile(`(?i)plaintext (password|credential|data|key|secret)`),
                        "Weak RSA Key":           regexp.MustCompile(`RSA-2048`),
                        "Weak Encryption Mode":   regexp.MustCompile(`(?i)(CBC mode|ECB mode)`),
                        "Weak Password Hashing":  regexp.MustCompile(`(?i)(PBKDF2 < \d+ iterations|md5 for password|sha1 for password)`),
                        "Weak Encryption":        regexp.MustCompile(`(?i)(AES-128|DES|3DES)`),
                },
        }
}

// Detect scans a file for cryptographic assets
func (d *Detector) Detect(path string, content []byte) ([]types.Finding, error) {
        var findings []types.Finding

        // Get filename for crypto-related file checks
        filename := filepath.Base(path)
        
        // Check extension for crypto-related files
        if isCryptoExtension(filepath.Ext(path)) {
                findings = append(findings, types.Finding{
                        File:            path,
                        Type:            "Crypto File Extension",
                        Description:     "File with cryptographic-related extension detected",
                        LineNumber:      0,
                        Content:         "File with cryptographic-related extension",
                        Severity:        "MEDIUM",
                        Vulnerable:      false,
                        Vulnerabilities: []types.Vulnerability{},
                })
        }

        // Check filename for crypto-related files
        if isCryptoFilename(filename) {
                findings = append(findings, types.Finding{
                        File:            path,
                        Type:            "Crypto File",
                        Description:     "Cryptographic asset file detected",
                        LineNumber:      0,
                        Content:         "File with cryptographic-related name",
                        Severity:        "MEDIUM",
                        Vulnerable:      false,
                        Vulnerabilities: []types.Vulnerability{},
                })
        }

        // Check for crypto implementations based on file path
        if isCryptoImplementation(path) {
                findings = append(findings, types.Finding{
                        File:            path,
                        Type:            "Crypto Implementation",
                        Description:     "Cryptographic implementation file detected",
                        LineNumber:      0,
                        Content:         "File with cryptographic implementation",
                        Severity:        "LOW",
                        Vulnerable:      false,
                        Vulnerabilities: []types.Vulnerability{},
                })
        }

        // Check for patterns in file content
        lines := bytes.Split(content, []byte("\n"))
        for patternName, pattern := range d.patterns {
                matches := pattern.FindAll(content, -1)
                for _, match := range matches {
                        // Find line number
                        lineNum := 0
                        for i, line := range lines {
                                if bytes.Contains(line, match) {
                                        lineNum = i + 1
                                        break
                                }
                        }

                        // Determine severity based on the type of finding
                        severity := "HIGH"
                        if patternName == "Certificate" {
                                severity = "MEDIUM"
                        }
                        
                        // LOW severity patterns
                        if patternName == "Security TODO Comment" || 
                           patternName == "Crypto FIXME Comment" || 
                           patternName == "Password Reference" || 
                           patternName == "Plaintext Reference" || 
                           patternName == "Weak RSA Key" || 
                           patternName == "Weak Encryption Mode" || 
                           patternName == "Weak Password Hashing" || 
                           patternName == "Weak Encryption" ||
                           patternName == "Public Key" {
                                severity = "LOW"
                        }

                        findings = append(findings, types.Finding{
                                File:        path,
                                Type:        patternName,
                                Description: "Found " + patternName,
                                LineNumber:  lineNum,
                                Content:     string(match),
                                Severity:    severity,
                                Vulnerable:  false,
                        })
                }
        }

        // Check for base64-encoded data that might be cryptographic
        if potentialBase64 := findPotentialBase64(content); potentialBase64 != "" {
                findings = append(findings, types.Finding{
                        File:        path,
                        Type:        "Potential Encoded Key",
                        Description: "Found potential base64-encoded key",
                        LineNumber:  0, // Would need more complex logic to determine line number
                        Content:     potentialBase64,
                        Severity:    "MEDIUM",
                        Vulnerable:  false,
                })
        }

        return findings, nil
}

// isCryptoFilename checks if a filename is related to cryptography
func isCryptoFilename(filename string) bool {
        cryptoFiles := []string{
                "id_rsa", "id_dsa", "authorized_keys", "known_hosts",
                "private-key", "public-key", "ssl", "tls", "gpg",
        }

        for _, cryptoFile := range cryptoFiles {
                if filename == cryptoFile {
                        return true
                }
        }

        return false
}

// isCryptoExtension checks if a file extension is related to cryptography
func isCryptoExtension(ext string) bool {
        cryptoExts := []string{
                ".pem", ".key", ".keystore", ".p12", ".pfx", ".jks", ".cer", ".crt", ".pub",
        }

        for _, cryptoExt := range cryptoExts {
                if ext == cryptoExt {
                        return true
                }
        }

        return false
}

// isCryptoImplementation checks if a file might contain crypto implementations
func isCryptoImplementation(path string) bool {
        // Check for paths that might contain crypto implementations
        cryptoPaths := []string{
                "crypto", "cipher", "encryption", "decrypt", "encrypt",
                "tls", "ssl", "rsa", "aes", "sha", "md5", "hash",
        }

        for _, cryptoPath := range cryptoPaths {
                if filepath.Base(path) == cryptoPath || 
                   bytes.Contains([]byte(path), []byte("/"+cryptoPath+"/")) ||
                   bytes.Contains([]byte(path), []byte("\\"+cryptoPath+"\\")) {
                        return true
                }
        }

        return false
}

// findPotentialBase64 looks for strings that might be base64-encoded keys
func findPotentialBase64(content []byte) string {
        // Look for long base64-encoded strings (at least 40 chars)
        re := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,3}`)
        matches := re.FindAll(content, -1)
        
        for _, match := range matches {
                // Try to decode and see if it might be a key
                decoded, err := base64.StdEncoding.DecodeString(string(match))
                if err != nil {
                        continue
                }
                
                // Check if decoded content looks like binary data with some printable chars
                isPrintable := 0
                for _, b := range decoded {
                        if b >= 32 && b <= 126 {
                                isPrintable++
                        }
                }
                
                // If it's mixed binary and text, it might be a key
                if isPrintable > 0 && isPrintable < len(decoded) {
                        return string(match)
                }
        }
        
        return ""
}
