package spinner

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewSpinner tests creating a new spinner
func TestNewSpinner(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer
	
	// Create a spinner with default frames
	spinner := NewSpinner("Test spinner", &buf)
	
	// Check that the spinner was created with correct properties
	assert.NotNil(t, spinner)
	assert.Equal(t, "Test spinner", spinner.message)
	assert.Equal(t, DefaultRefreshRate, spinner.refreshRate)
	assert.Equal(t, true, spinner.hideCursor)
	assert.Equal(t, defaultSpinnerFrames, spinner.frames)
	assert.Equal(t, &buf, spinner.writer)
	assert.Equal(t, false, spinner.active)
	
	// Create a spinner with custom frames and options
	customFrames := []string{"A", "B", "C"}
	spinner = NewSpinner("Custom spinner", &buf, WithFrames(customFrames), WithRefreshRate(100*time.Millisecond), WithHideCursor(false))
	
	assert.Equal(t, "Custom spinner", spinner.message)
	assert.Equal(t, 100*time.Millisecond, spinner.refreshRate)
	assert.Equal(t, false, spinner.hideCursor)
	assert.Equal(t, customFrames, spinner.frames)
}

// TestWithFrames tests the WithFrames option
func TestWithFrames(t *testing.T) {
	customFrames := []string{"A", "B", "C"}
	option := WithFrames(customFrames)
	
	var s Spinner
	option(&s)
	
	assert.Equal(t, customFrames, s.frames)
}

// TestWithRefreshRate tests the WithRefreshRate option
func TestWithRefreshRate(t *testing.T) {
	refreshRate := 200 * time.Millisecond
	option := WithRefreshRate(refreshRate)
	
	var s Spinner
	option(&s)
	
	assert.Equal(t, refreshRate, s.refreshRate)
}

// TestWithHideCursor tests the WithHideCursor option
func TestWithHideCursor(t *testing.T) {
	option := WithHideCursor(false)
	
	var s Spinner
	s.hideCursor = true
	option(&s)
	
	assert.Equal(t, false, s.hideCursor)
}

// TestRenderFrame tests rendering a single frame
func TestRenderFrame(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer
	
	spinner := NewSpinner("Test message", &buf)
	spinner.renderFrame(0)
	
	// Check that the frame was rendered to the buffer
	output := buf.String()
	assert.Contains(t, output, spinner.frames[0])
	assert.Contains(t, output, "Test message")
}

// TestUpdateMessage tests updating the spinner message
func TestUpdateMessage(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner("Initial message", &buf)
	
	// Update the message
	spinner.UpdateMessage("Updated message")
	
	// Check that the message was updated
	assert.Equal(t, "Updated message", spinner.message)
}

// TestCompleteMessage tests setting the completion message
func TestCompleteMessage(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner("Working...", &buf)
	
	// Set completion message
	spinner.CompleteMessage("Done!")
	
	// Check that the completion message was set
	assert.Equal(t, "Done!", spinner.completeMessage)
}

// TestErrorMessage tests setting the error message
func TestErrorMessage(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner("Working...", &buf)
	
	// Set error message
	spinner.ErrorMessage("Failed!")
	
	// Check that the error message was set
	assert.Equal(t, "Failed!", spinner.errorMessage)
}

// TestStart tests starting the spinner
// This is a more complex test as it involves goroutines
func TestStart(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner("Starting...", &buf, WithRefreshRate(10*time.Millisecond))
	
	// Start the spinner
	spinner.Start()
	
	// Check that the spinner is marked as active
	assert.True(t, spinner.active)
	
	// Give it some time to render a few frames
	time.Sleep(50 * time.Millisecond)
	
	// Stop the spinner
	spinner.Stop()
	
	// Check that the spinner is no longer active
	assert.False(t, spinner.active)
	
	// Check that something was written to the buffer
	assert.NotEmpty(t, buf.String())
}

// TestStop tests stopping the spinner
func TestStop(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner("Working...", &buf)
	
	// Manually set active
	spinner.active = true
	spinner.Stop()
	
	// Check that the spinner is no longer active
	assert.False(t, spinner.active)
}

// TestComplete tests completing the spinner successfully
func TestComplete(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner("Working...", &buf)
	spinner.CompleteMessage("Done!")
	
	// Manually set active
	spinner.active = true
	spinner.Complete()
	
	// Check that the spinner is no longer active
	assert.False(t, spinner.active)
	
	// Check that the completion message was written
	output := buf.String()
	assert.Contains(t, output, "Done!")
}

// TestError tests completing the spinner with an error
func TestError(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner("Working...", &buf)
	spinner.ErrorMessage("Failed!")
	
	// Manually set active
	spinner.active = true
	spinner.Error()
	
	// Check that the spinner is no longer active
	assert.False(t, spinner.active)
	
	// Check that the error message was written
	output := buf.String()
	assert.Contains(t, output, "Failed!")
}