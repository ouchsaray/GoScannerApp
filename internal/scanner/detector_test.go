package scanner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDetector(t *testing.T) {
	detector := NewDetector()
	assert.NotNil(t, detector)
	assert.NotEmpty(t, detector.patterns)
}

func TestDetectPattern(t *testing.T) {
	detector := NewDetector()
	
	tests := []struct {
		name        string
		content     string
		shouldMatch bool
		matchType   string
		severity    string
	}{
		{
			name:        "AWS Access Key",
			content:     "AKIAIOSFODNN7EXAMPLE",
			shouldMatch: true,
			matchType:   "AWS Access Key",
			severity:    "CRITICAL",
		},
		{
			name:        "Google API Key",
			content:     "AIzaSyDgElLI_RJ8WJ7TOcjHJBaZrj2WhFP7uQk",
			shouldMatch: true,
			matchType:   "Google API Key",
			severity:    "CRITICAL",
		},
		{
			name:        "GitHub Token",
			content:     "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			shouldMatch: true,
			matchType:   "GitHub Token",
			severity:    "CRITICAL",
		},
		{
			name:        "JWT Token",
			content:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
			shouldMatch: true,
			matchType:   "JWT Token",
			severity:    "CRITICAL",
		},
		{
			name:        "RSA Private Key",
			content:     "-----BEGIN RSA PRIVATE KEY-----\nMIIBOQIBAAJAVPfCvQw9N5i/G5fQVfGWnkA/kGZ\n-----END RSA PRIVATE KEY-----",
			shouldMatch: true,
			matchType:   "RSA Private Key",
			severity:    "CRITICAL",
		},
		{
			name:        "Weak Encryption Algorithm",
			content:     "crypto.CreateEncryptor(CipherMode.DES)",
			shouldMatch: true,
			matchType:   "Weak Encryption",
			severity:    "HIGH",
		},
		{
			name:        "Weak Cipher Mode",
			content:     "cipher.NewCBCDecrypter(block, iv)",
			shouldMatch: true,
			matchType:   "Insecure Mode",
			severity:    "HIGH",
		},
		{
			name:        "Weak Password Hashing",
			content:     "crypto.createHash('md5').update(password)",
			shouldMatch: true,
			matchType:   "Weak Password Hashing",
			severity:    "HIGH",
		},
		{
			name:        "Security TODO",
			content:     "// TODO: Fix this security vulnerability",
			shouldMatch: true,
			matchType:   "Security Comment",
			severity:    "LOW",
		},
		{
			name:        "Crypto FIXME",
			content:     "// FIXME: Replace weak crypto algorithm",
			shouldMatch: true,
			matchType:   "Crypto Comment",
			severity:    "LOW",
		},
		{
			name:        "Regular code - no match",
			content:     "func main() { fmt.Println(\"Hello World\") }",
			shouldMatch: false,
		},
		{
			name:        "Regular TODO - no match",
			content:     "// TODO: Add more features",
			shouldMatch: false,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, finding := detector.DetectPattern(tc.content, "test.go", 1)
			
			assert.Equal(t, tc.shouldMatch, match)
			
			if tc.shouldMatch {
				assert.Equal(t, tc.matchType, finding.Type)
				assert.Equal(t, tc.severity, finding.Severity)
				assert.Equal(t, "test.go", finding.File)
				assert.Equal(t, 1, finding.LineNumber)
				assert.Equal(t, tc.content, finding.Content)
				assert.NotEmpty(t, finding.Description)
				
				// Check if vulnerability is added based on severity
				hasVulnerabilities := finding.Severity == "CRITICAL" || finding.Severity == "HIGH" || finding.Severity == "MEDIUM"
				assert.Equal(t, hasVulnerabilities, finding.Vulnerable)
				if hasVulnerabilities {
					assert.NotEmpty(t, finding.Vulnerabilities)
				}
			}
		})
	}
}

func TestAnalyzeContent(t *testing.T) {
	detector := NewDetector()

	// Test file with multiple detectable patterns
	fileContent := `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {
	// TODO: Fix this insecure code
	apiKey := "AIzaSyDgElLI_RJ8WJ7TOcjHJBaZrj2WhFP7uQk"
	
	// FIXME: Use a more secure algorithm
	password := "hardcoded_password"
	
	// Use weak encryption
	block, _ := aes.NewCipher([]byte("0123456789ABCDEF"))
	mode := cipher.NewCBCDecrypter(block, []byte("INITIALIZATION V"))
	
	// Use weak hashing
	hashFunc := "md5"
	fmt.Println(hashFunc)
}
`

	findings := detector.AnalyzeContent(fileContent, "test.go")
	
	// We should have at least 4 findings (API key, password, CBC mode, weak hash)
	assert.GreaterOrEqual(t, len(findings), 4)
	
	// Check if we have the expected types of findings
	foundTypes := make(map[string]bool)
	for _, finding := range findings {
		foundTypes[finding.Type] = true
		
		// All findings should have the correct file
		assert.Equal(t, "test.go", finding.File)
		
		// Line numbers should be set
		assert.Greater(t, finding.LineNumber, 0)
		
		// Content should not be empty
		assert.NotEmpty(t, finding.Content)
	}
	
	// Verify we found at least these types
	expectedTypes := []string{
		"Google API Key",
		"Security Comment",
		"Password Reference",
	}
	
	for _, expectedType := range expectedTypes {
		assert.True(t, foundTypes[expectedType], "Expected to find %s", expectedType)
	}
}

func TestExtractVulnerabilities(t *testing.T) {
	detector := NewDetector()
	
	// Test cases for each vulnerability type
	tests := []struct {
		name        string
		pattern     string
		content     string
		vulnType    string
		description string
		severity    string
	}{
		{
			name:        "Key Exposure",
			pattern:     "RSA PRIVATE KEY",
			content:     "-----BEGIN RSA PRIVATE KEY-----",
			vulnType:    "Key Exposure",
			description: "Private key material checked into repository",
			severity:    "CRITICAL",
		},
		{
			name:        "Hardcoded Credential",
			pattern:     "API_KEY",
			content:     "API_KEY=abc123",
			vulnType:    "Hardcoded Credential",
			description: "Hardcoded credential in source code",
			severity:    "CRITICAL",
		},
		{
			name:        "Weak Algorithm",
			pattern:     "DES",
			content:     "crypto.createCipher('des')",
			vulnType:    "Weak Algorithm",
			description: "Using weak or deprecated algorithm: DES",
			severity:    "HIGH",
		},
		{
			name:        "Insecure Mode",
			pattern:     "ECB",
			content:     "cipher.mode.ECB",
			vulnType:    "Insecure Mode",
			description: "Using insecure cipher mode: ECB",
			severity:    "HIGH",
		},
		{
			name:        "Suboptimal Practice",
			pattern:     "CBC",
			content:     "CBC mode",
			vulnType:    "Suboptimal Practice",
			description: "Using practice that could be improved: CBC",
			severity:    "LOW",
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vulns := detector.extractVulnerabilities(tc.pattern, tc.content)
			
			assert.NotEmpty(t, vulns)
			foundMatch := false
			
			for _, vuln := range vulns {
				if strings.Contains(vuln.Type, tc.vulnType) && 
				   strings.Contains(vuln.Description, tc.description) &&
				   vuln.Severity == tc.severity {
					foundMatch = true
					break
				}
			}
			
			assert.True(t, foundMatch, "Expected to find vulnerability of type %s with description containing %s", 
				tc.vulnType, tc.description)
		})
	}
}

func TestGetPatternDescription(t *testing.T) {
	detector := NewDetector()
	
	tests := []struct {
		name        string
		patternType string
		expected    string
	}{
		{
			name:        "AWS Access Key",
			patternType: "AWS Access Key",
			expected:    "Found AWS Access Key",
		},
		{
			name:        "Google API Key",
			patternType: "Google API Key",
			expected:    "Found Google API Key",
		},
		{
			name:        "GitHub Token",
			patternType: "GitHub Token",
			expected:    "Found GitHub Token",
		},
		{
			name:        "JWT Token",
			patternType: "JWT Token",
			expected:    "Found JWT Token",
		},
		{
			name:        "RSA Private Key",
			patternType: "RSA Private Key",
			expected:    "Found RSA Private Key",
		},
		{
			name:        "Security Comment",
			patternType: "Security Comment",
			expected:    "Found security-related comment",
		},
		{
			name:        "Unknown Type",
			patternType: "Unknown",
			expected:    "Found cryptographic asset",
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			description := detector.getPatternDescription(tc.patternType)
			assert.Equal(t, tc.expected, description)
		})
	}
}