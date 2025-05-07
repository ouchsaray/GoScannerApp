package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestDashboardCmd tests the dashboard command
func TestDashboardCmd(t *testing.T) {
	// Create a new dashboard command
	cmd := dashboardCmd()
	
	// Check that the command is properly configured
	assert.Equal(t, "dashboard", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	
	// Test with no arguments (should fail)
	output := executeCmdWithArgs(t, cmd, []string{})
	assert.Contains(t, output, "Error: requires at least 1 arg(s)")
}

// TestDashboardCmdWithArgs tests the dashboard command with arguments
func TestDashboardCmdWithArgs(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "dashboard-test")
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
	
	// Create a new dashboard command
	cmd := dashboardCmd()
	
	// Set flags that will make the scan quick and targeted
	cmd.Flags().Set("skip-git", "true")
	cmd.Flags().Set("exclude", "*.md,*.txt")
	
	// Test with a valid argument but using --skip-git to avoid actual scanning
	// This is just a basic test to ensure the command doesn't crash
	output := executeCmdWithArgs(t, cmd, []string{tmpDir})
	
	// In a real test environment, you might assert on specific output patterns
	// Here we're just making sure it didn't crash
	assert.NotEmpty(t, output)
}