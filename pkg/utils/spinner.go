package utils

import (
	"fmt"
	"strings"
	"time"
)

// Spinner represents an animated loading spinner
type Spinner struct {
	frames      []string
	message     string
	currentIdx  int
	lastUpdate  time.Time
	interval    time.Duration
	stopChan    chan bool
	active      bool
	formatReset string
	formatClear string
	hideCursor  bool
}

// SpinnerOptions contains configuration for a Spinner
type SpinnerOptions struct {
	Interval   time.Duration
	HideCursor bool
}

// NewSpinner creates a new spinner with the given message
func NewSpinner(message string, opts ...SpinnerOptions) *Spinner {
	// Default frames for the spinner
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	
	// Default interval
	interval := time.Millisecond * 100
	hideCursor := true
	
	// Apply options if provided
	if len(opts) > 0 {
		if opts[0].Interval > 0 {
			interval = opts[0].Interval
		}
		hideCursor = opts[0].HideCursor
	}
	
	return &Spinner{
		frames:      frames,
		message:     message,
		currentIdx:  0,
		interval:    interval,
		stopChan:    make(chan bool),
		formatReset: "\033[0m",
		formatClear: "\r\033[K",
		hideCursor:  hideCursor,
	}
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	if s.active {
		return
	}
	s.active = true
	
	// Hide cursor if requested
	if s.hideCursor {
		fmt.Print("\033[?25l")
	}
	
	go func() {
		for {
			select {
			case <-s.stopChan:
				return
			default:
				s.update()
				time.Sleep(s.interval)
			}
		}
	}()
}

// Stop ends the spinner animation
func (s *Spinner) Stop() {
	if !s.active {
		return
	}
	
	s.stopChan <- true
	s.active = false
	
	// Clear the spinner line
	fmt.Print(s.formatClear)
	
	// Show cursor again if it was hidden
	if s.hideCursor {
		fmt.Print("\033[?25h")
	}
}

// UpdateMessage changes the message shown with the spinner
func (s *Spinner) UpdateMessage(message string) {
	s.message = message
}

// update renders the next frame of the spinner
func (s *Spinner) update() {
	// Get current frame
	frame := s.frames[s.currentIdx]
	
	// Move to next frame
	s.currentIdx = (s.currentIdx + 1) % len(s.frames)
	
	// Print the spinner and message
	fmt.Printf("%s%s %s%s", s.formatClear, frame, s.message, s.formatReset)
}

// MultiSpinner allows for multiple loading states to be displayed
type MultiSpinner struct {
	spinners    []*Spinner
	messages    []string
	states      []string
	stopChan    chan bool
	active      bool
	hideCursor  bool
}

// NewMultiSpinner creates a new multi-stage spinner
func NewMultiSpinner(messages []string) *MultiSpinner {
	states := make([]string, len(messages))
	for i := range states {
		states[i] = "pending" // pending, in-progress, complete, error
	}
	
	return &MultiSpinner{
		messages:   messages,
		states:     states,
		stopChan:   make(chan bool),
		hideCursor: true,
	}
}

// Start begins the multi-spinner animation
func (ms *MultiSpinner) Start() {
	if ms.active {
		return
	}
	ms.active = true
	
	// Hide cursor if requested
	if ms.hideCursor {
		fmt.Print("\033[?25l")
	}
	
	go func() {
		for {
			select {
			case <-ms.stopChan:
				return
			default:
				ms.render()
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// Stop ends the multi-spinner animation
func (ms *MultiSpinner) Stop() {
	if !ms.active {
		return
	}
	
	ms.stopChan <- true
	ms.active = false
	
	// Show cursor again if it was hidden
	if ms.hideCursor {
		fmt.Print("\033[?25h")
	}
}

// CompleteStage marks a stage as complete
func (ms *MultiSpinner) CompleteStage(index int) {
	if index >= 0 && index < len(ms.states) {
		ms.states[index] = "complete"
	}
}

// FailStage marks a stage as failed
func (ms *MultiSpinner) FailStage(index int) {
	if index >= 0 && index < len(ms.states) {
		ms.states[index] = "error"
	}
}

// StartStage marks a stage as in progress
func (ms *MultiSpinner) StartStage(index int) {
	if index >= 0 && index < len(ms.states) {
		ms.states[index] = "in-progress"
	}
}

// render updates the display of all stages
func (ms *MultiSpinner) render() {
	// Clear previous lines
	fmt.Print(strings.Repeat("\033[1A\033[K", len(ms.messages)))
	
	// Animation frames
	spinFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frame := spinFrames[time.Now().UnixNano()/100000000 % int64(len(spinFrames))]
	
	// Render each stage
	for i, msg := range ms.messages {
		var icon string
		switch ms.states[i] {
		case "pending":
			icon = "○"
		case "in-progress":
			icon = frame
		case "complete":
			icon = "✓"
		case "error":
			icon = "✗"
		}
		
		// Different colors for different states
		var colorCode string
		switch ms.states[i] {
		case "pending":
			colorCode = "\033[90m" // Gray
		case "in-progress":
			colorCode = "\033[93m" // Yellow
		case "complete":
			colorCode = "\033[92m" // Green
		case "error":
			colorCode = "\033[91m" // Red
		}
		
		fmt.Printf("%s%s %s\033[0m\n", colorCode, icon, msg)
	}
}