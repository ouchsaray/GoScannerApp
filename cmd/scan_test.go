package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestScanCmd tests the scan command
func TestScanCmd(t *testing.T) {
	// Create a new scan command
	cmd := scanCmd()
	
	// Check that the command is properly configured
	assert.Equal(t, "scan", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	
	// Test with no arguments (should fail)
	output := executeCmdWithArgs(t, cmd, []string{})
	assert.Contains(t, output, "Error: requires at least 1 arg(s)")
}

// TestScanCmdWithArgs tests the scan command with arguments
func TestScanCmdWithArgs(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "scan-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create a test file in the temporary directory
	testFilePath := tmpDir + "/test.go"
	err = os.WriteFile(testFilePath, []byte(`package main

func main() {
	// This is a test file
	apiKey := "not-a-real-key" // This should not trigger detection in tests
}`), 0644)
	assert.NoError(t, err)
	
	// Create a new scan command
	cmd := scanCmd()
	
	// Set flags that will make the scan quick and targeted
	cmd.Flags().Set("skip-git", "true")
	cmd.Flags().Set("exclude", "*.md,*.txt")
	
	// Test with a valid argument but using --skip-git to avoid actual scanning
	// Note: This may still attempt to scan, but we're mostly just checking that the command doesn't crash
	output := executeCmdWithArgs(t, cmd, []string{tmpDir})
	
	// In a real test environment, you might assert on specific output patterns
	// Here we're just making sure it didn't crash
	assert.NotEmpty(t, output)
}

// Helper function to execute a command with arguments and capture output
func executeCmdWithArgs(t *testing.T, cmd *cobra.Command, args []string) string {
	t.Helper()
	
	// Save original stdout and create a buffer to capture output
	oldOut := os.Stdout
	var buf bytes.Buffer
	os.Stdout = bytes.NewBufferString("")
	
	// Set command arguments
	cmd.SetArgs(args)
	
	// Execute the command
	cmd.Execute()
	
	// Restore original stdout
	out := os.Stdout.(*bytes.Buffer).String()
	os.Stdout = oldOut
	
	return out
}