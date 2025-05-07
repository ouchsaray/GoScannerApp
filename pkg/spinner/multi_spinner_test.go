package spinner

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewMultiSpinner tests creating a new MultiSpinner
func TestNewMultiSpinner(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer
	
	// Create a multi-spinner
	ms := NewMultiSpinner(&buf)
	
	// Check that the multi-spinner was created with correct properties
	assert.NotNil(t, ms)
	assert.Equal(t, &buf, ms.writer)
	assert.Equal(t, false, ms.active)
	assert.Empty(t, ms.spinners)
}

// TestAddSpinner tests adding spinners to a MultiSpinner
func TestAddSpinner(t *testing.T) {
	var buf bytes.Buffer
	ms := NewMultiSpinner(&buf)
	
	// Add spinners with different messages
	spinner1 := ms.AddSpinner("Task 1")
	spinner2 := ms.AddSpinner("Task 2")
	
	// Check that the spinners were added
	assert.Len(t, ms.spinners, 2)
	assert.Equal(t, "Task 1", spinner1.message)
	assert.Equal(t, "Task 2", spinner2.message)
	
	// Check that the spinners are in the correct order
	assert.Equal(t, spinner1, ms.spinners[0])
	assert.Equal(t, spinner2, ms.spinners[1])
}

// TestStart tests starting the MultiSpinner
func TestStart(t *testing.T) {
	var buf bytes.Buffer
	ms := NewMultiSpinner(&buf)
	
	// Add spinners
	spinner1 := ms.AddSpinner("Task 1")
	spinner2 := ms.AddSpinner("Task 2")
	
	// Start the multi-spinner
	ms.Start()
	
	// Check that the multi-spinner is marked as active
	assert.True(t, ms.active)
	
	// Give it some time to render a few frames
	time.Sleep(50 * time.Millisecond)
	
	// Complete one of the tasks
	spinner1.Complete()
	
	// Wait for the next update
	time.Sleep(50 * time.Millisecond)
	
	// Complete the remaining task
	spinner2.Complete()
	
	// Wait for all updates to finish
	time.Sleep(50 * time.Millisecond)
	
	// Stop the multi-spinner
	ms.Stop()
	
	// Check that the multi-spinner is no longer active
	assert.False(t, ms.active)
	
	// Check that something was written to the buffer
	assert.NotEmpty(t, buf.String())
}

// TestStop tests stopping the MultiSpinner
func TestStop(t *testing.T) {
	var buf bytes.Buffer
	ms := NewMultiSpinner(&buf)
	
	// Add spinners
	ms.AddSpinner("Task 1")
	ms.AddSpinner("Task 2")
	
	// Manually set active
	ms.active = true
	ms.Stop()
	
	// Check that the multi-spinner is no longer active
	assert.False(t, ms.active)
}

// TestUpdateSpinners tests updating spinners in a MultiSpinner
func TestUpdateSpinners(t *testing.T) {
	var buf bytes.Buffer
	ms := NewMultiSpinner(&buf)
	
	// Add spinners
	spinner1 := ms.AddSpinner("Task 1")
	spinner2 := ms.AddSpinner("Task 2")
	
	// Update the spinners
	spinner1.UpdateMessage("Updated Task 1")
	spinner2.CompleteMessage("Task 2 Done!")
	
	// Check that the messages were updated
	assert.Equal(t, "Updated Task 1", spinner1.message)
	assert.Equal(t, "Task 2 Done!", spinner2.completeMessage)
}

// TestRenderSpinners tests rendering all spinners
func TestRenderSpinners(t *testing.T) {
	var buf bytes.Buffer
	ms := NewMultiSpinner(&buf)
	
	// Add spinners
	ms.AddSpinner("Task 1")
	ms.AddSpinner("Task 2")
	
	// Manually render the spinners
	ms.renderSpinners(0)
	
	// Check that something was written to the buffer
	output := buf.String()
	assert.Contains(t, output, "Task 1")
	assert.Contains(t, output, "Task 2")
}

// TestGetSpinnerFrames tests getting spinner frames
func TestGetSpinnerFrames(t *testing.T) {
	// Test the default frames
	frames := getSpinnerFrames("")
	assert.Equal(t, defaultSpinnerFrames, frames)
	
	// Test the dots frames
	frames = getSpinnerFrames("dots")
	assert.Equal(t, dotsFrames, frames)
	
	// Test the line frames
	frames = getSpinnerFrames("line")
	assert.Equal(t, lineFrames, frames)
	
	// Test an unknown type (should return default)
	frames = getSpinnerFrames("unknown")
	assert.Equal(t, defaultSpinnerFrames, frames)
}

// TestMultiSpinnerCompletionDetection tests that the MultiSpinner detects when all spinners are complete
func TestMultiSpinnerCompletionDetection(t *testing.T) {
	var buf bytes.Buffer
	ms := NewMultiSpinner(&buf)
	
	// Add spinners
	spinner1 := ms.AddSpinner("Task 1")
	spinner2 := ms.AddSpinner("Task 2")
	
	// Start the multi-spinner
	ms.Start()
	
	// Complete both spinners
	spinner1.Complete()
	spinner2.Complete()
	
	// Wait for the multi-spinner to detect completion
	time.Sleep(200 * time.Millisecond)
	
	// Check that the multi-spinner is no longer active
	assert.False(t, ms.active)
}