package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewScanner(t *testing.T) {
	// Test creating a new scanner with various options
	tests := []struct {
		name     string
		options  []ScannerOption
		expected Scanner
	}{
		{
			name:    "Default scanner",
			options: []ScannerOption{},
			expected: Scanner{
				verbose:        false,
				skipGit:        false,
				excludePattern: nil,
				findings:       []Finding{},
			},
		},
		{
			name:    "Verbose scanner",
			options: []ScannerOption{WithVerbose(true)},
			expected: Scanner{
				verbose:        true,
				skipGit:        false,
				excludePattern: nil,
				findings:       []Finding{},
			},
		},
		{
			name:    "Skip git scanner",
			options: []ScannerOption{WithSkipGit(true)},
			expected: Scanner{
				verbose:        false,
				skipGit:        true,
				excludePattern: nil,
				findings:       []Finding{},
			},
		},
		{
			name:    "With exclude pattern",
			options: []ScannerOption{WithExcludePattern([]string{"*.md", "*.txt"})},
			expected: Scanner{
				verbose:        false,
				skipGit:        false,
				excludePattern: []string{"*.md", "*.txt"},
				findings:       []Finding{},
			},
		},
		{
			name: "With all options",
			options: []ScannerOption{
				WithVerbose(true),
				WithSkipGit(true),
				WithExcludePattern([]string{"*.md", "*.txt"}),
			},
			expected: Scanner{
				verbose:        true,
				skipGit:        true,
				excludePattern: []string{"*.md", "*.txt"},
				findings:       []Finding{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scanner := NewScanner(tc.options...)
			assert.Equal(t, tc.expected.verbose, scanner.verbose)
			assert.Equal(t, tc.expected.skipGit, scanner.skipGit)
			assert.Equal(t, tc.expected.excludePattern, scanner.excludePattern)
			assert.Empty(t, scanner.findings)
		})
	}
}

func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		excludePatterns []string
		expected        bool
	}{
		{
			name:            "No exclude patterns",
			path:            "test.go",
			excludePatterns: nil,
			expected:        false,
		},
		{
			name:            "Exclude txt files",
			path:            "test.txt",
			excludePatterns: []string{"*.txt"},
			expected:        true,
		},
		{
			name:            "Exclude md files but check go file",
			path:            "test.go",
			excludePatterns: []string{"*.md"},
			expected:        false,
		},
		{
			name:            "Exclude multiple patterns with match",
			path:            "test.md",
			excludePatterns: []string{"*.md", "*.txt"},
			expected:        true,
		},
		{
			name:            "Exclude directory",
			path:            "node_modules/test.js",
			excludePatterns: []string{"node_modules/*"},
			expected:        true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scanner := NewScanner(WithExcludePattern(tc.excludePatterns))
			assert.Equal(t, tc.expected, scanner.shouldExclude(tc.path))
		})
	}
}

func TestAddFinding(t *testing.T) {
	scanner := NewScanner()
	
	// Add a finding and check it was added
	finding := Finding{
		Type:        "Test Type",
		Severity:    "HIGH",
		File:        "test.go",
		LineNumber:  10,
		Content:     "test content",
		Description: "Test description",
		Vulnerable:  true,
	}
	
	scanner.addFinding(finding)
	assert.Len(t, scanner.findings, 1)
	assert.Equal(t, finding, scanner.findings[0])
	
	// Add another finding
	finding2 := Finding{
		Type:        "Another Type",
		Severity:    "LOW",
		File:        "another.go",
		LineNumber:  20,
		Content:     "another content",
		Description: "Another description",
		Vulnerable:  false,
	}
	
	scanner.addFinding(finding2)
	assert.Len(t, scanner.findings, 2)
	assert.Equal(t, finding2, scanner.findings[1])
}

// Basic test for GetFindings
func TestGetFindings(t *testing.T) {
	scanner := NewScanner()
	
	// Initially empty
	assert.Empty(t, scanner.GetFindings())
	
	// Add findings
	finding1 := Finding{Type: "Type1", Severity: "HIGH"}
	finding2 := Finding{Type: "Type2", Severity: "LOW"}
	
	scanner.addFinding(finding1)
	scanner.addFinding(finding2)
	
	// Check findings are returned
	findings := scanner.GetFindings()
	assert.Len(t, findings, 2)
	assert.Equal(t, finding1, findings[0])
	assert.Equal(t, finding2, findings[1])
}

// TestScanFile tests the scanFile method with a temporary test file
func TestScanFile(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "scanner_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	// Create a test file with some content that would trigger detections
	testFilePath := filepath.Join(tempDir, "test.go")
	testContent := `package main

// TODO: Fix this insecure implementation
func main() {
	apiKey := "AIzaSyCrVYMKA7fHJ95-0R5aNKK39cKE3DzN_zw" // Google API Key
	password := "SuperSecretPassword123" // Plaintext password
	// FIXME: Use more secure crypto
	const weakHash = "md5"
}
`
	err = os.WriteFile(testFilePath, []byte(testContent), 0644)
	assert.NoError(t, err)
	
	// Create a scanner and scan the file
	scanner := NewScanner(WithVerbose(true))
	err = scanner.scanFile(testFilePath)
	assert.NoError(t, err)
	
	// Check that findings were generated
	findings := scanner.GetFindings()
	assert.NotEmpty(t, findings)
	
	// Check for specific types of findings
	// This will vary based on how your detector is implemented
	// Here I'm just checking that some findings were generated
	assert.GreaterOrEqual(t, len(findings), 1)
}