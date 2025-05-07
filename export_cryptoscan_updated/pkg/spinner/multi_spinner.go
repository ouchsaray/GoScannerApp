package spinner

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Stage represents a step in a multi-stage process
type Stage struct {
	Message string
	Status  string // "pending", "running", "success", "warning", "error"
}

// MultiSpinner represents a multi-stage spinner
type MultiSpinner struct {
	stages          []Stage
	animation       []string
	style           *Style
	writer          io.Writer
	stopChan        chan struct{}
	doneWait        *sync.WaitGroup
	animationIndex  int
	interval        time.Duration
	active          bool
	mutex           *sync.Mutex
	currentStage    int
	hideCursor      bool
	outputLineCount int
}

// NewMulti creates a new multi-stage spinner
func NewMulti(stages []string, animation []string) *MultiSpinner {
	stageObjects := make([]Stage, len(stages))
	for i, message := range stages {
		stageObjects[i] = Stage{
			Message: message,
			Status:  "pending",
		}
	}

	return &MultiSpinner{
		stages:     stageObjects,
		animation:  animation,
		style:      DefaultStyle(),
		writer:     os.Stdout,
		stopChan:   make(chan struct{}),
		doneWait:   &sync.WaitGroup{},
		interval:   100 * time.Millisecond,
		mutex:      &sync.Mutex{},
		hideCursor: true,
	}
}

// WithStyle sets a custom style for the multi-spinner
func (ms *MultiSpinner) WithStyle(style *Style) *MultiSpinner {
	ms.style = style
	return ms
}

// WithWriter sets a custom writer for the multi-spinner output
func (ms *MultiSpinner) WithWriter(writer io.Writer) *MultiSpinner {
	ms.writer = writer
	return ms
}

// WithInterval sets the animation interval
func (ms *MultiSpinner) WithInterval(interval time.Duration) *MultiSpinner {
	ms.interval = interval
	return ms
}

// WithoutCursorHiding disables cursor hiding
func (ms *MultiSpinner) WithoutCursorHiding() *MultiSpinner {
	ms.hideCursor = false
	return ms
}

// Start begins the multi-spinner animation
func (ms *MultiSpinner) Start() *MultiSpinner {
	ms.mutex.Lock()
	if ms.active {
		ms.mutex.Unlock()
		return ms
	}
	ms.active = true
	ms.mutex.Unlock()

	// Hide cursor if configured
	if ms.hideCursor {
		fmt.Fprint(ms.writer, "\033[?25l")
	}

	ms.doneWait.Add(1)
	go func() {
		defer ms.doneWait.Done()
		
		for {
			select {
			case <-ms.stopChan:
				return
			default:
				ms.mutex.Lock()
				ms.render()
				ms.mutex.Unlock()
				time.Sleep(ms.interval)
			}
		}
	}()

	return ms
}

// Stop stops the multi-spinner animation
func (ms *MultiSpinner) Stop() *MultiSpinner {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	if !ms.active {
		return ms
	}

	ms.active = false
	close(ms.stopChan)
	ms.doneWait.Wait()

	// Show cursor again if it was hidden
	if ms.hideCursor {
		fmt.Fprint(ms.writer, "\033[?25h")
	}
	
	// Reset spinner channel
	ms.stopChan = make(chan struct{})

	return ms
}

// Next advances to the next stage and marks it as running
func (ms *MultiSpinner) Next() *MultiSpinner {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	
	// Mark current stage as success if it's running
	if ms.currentStage < len(ms.stages) && ms.stages[ms.currentStage].Status == "running" {
		ms.stages[ms.currentStage].Status = "success"
	}
	
	// Move to next stage
	ms.currentStage++
	
	// Mark the new current stage as running
	if ms.currentStage < len(ms.stages) {
		ms.stages[ms.currentStage].Status = "running"
	}
	
	return ms
}

// UpdateStage updates the status of a specific stage
func (ms *MultiSpinner) UpdateStage(index int, status string) *MultiSpinner {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	
	if index >= 0 && index < len(ms.stages) {
		ms.stages[index].Status = status
	}
	
	return ms
}

// UpdateMessage updates the message of a specific stage
func (ms *MultiSpinner) UpdateMessage(index int, message string) *MultiSpinner {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	
	if index >= 0 && index < len(ms.stages) {
		ms.stages[index].Message = message
	}
	
	return ms
}

// StartStage marks a stage as running
func (ms *MultiSpinner) StartStage(index int) *MultiSpinner {
	return ms.UpdateStage(index, "running")
}

// SuccessStage marks a stage as successful
func (ms *MultiSpinner) SuccessStage(index int) *MultiSpinner {
	return ms.UpdateStage(index, "success")
}

// WarningStage marks a stage with a warning
func (ms *MultiSpinner) WarningStage(index int) *MultiSpinner {
	return ms.UpdateStage(index, "warning")
}

// ErrorStage marks a stage as failed
func (ms *MultiSpinner) ErrorStage(index int) *MultiSpinner {
	return ms.UpdateStage(index, "error")
}

// render draws all stages
func (ms *MultiSpinner) render() {
	if len(ms.stages) == 0 {
		return
	}
	
	// Clear previous output
	if ms.outputLineCount > 0 {
		// Move cursor to the beginning of the first line of previous output
		fmt.Fprint(ms.writer, strings.Repeat("\033[1A\033[K", ms.outputLineCount-1))
		fmt.Fprint(ms.writer, "\r\033[K")
	}
	
	// Get current animation frame
	ms.animationIndex = (ms.animationIndex + 1) % len(ms.animation)
	spinnerChar := ms.animation[ms.animationIndex]
	
	// Render all stages
	var output strings.Builder
	for i, stage := range ms.stages {
		var symbol, symbolColor string
		
		switch stage.Status {
		case "pending":
			symbol = "○"
			symbolColor = "\033[90m" // Gray
		case "running":
			symbol = spinnerChar
			symbolColor = ms.style.SymbolColor
		case "success":
			symbol = ms.style.SuccessSymbol
			symbolColor = ms.style.SuccessColor
		case "warning":
			symbol = ms.style.WarningSymbol
			symbolColor = ms.style.WarningColor
		case "error":
			symbol = ms.style.ErrorSymbol
			symbolColor = ms.style.ErrorColor
		default:
			symbol = "○"
			symbolColor = "\033[90m" // Gray
		}
		
		// Build line with color
		prefix := fmt.Sprintf("%s%s%s", symbolColor, symbol, "\033[0m")
		line := fmt.Sprintf("%s %s%s\n", prefix, ms.style.MessageColor, stage.Message)
		output.WriteString(line)
		
		// Highlight current stage with an indicator
		if i == ms.currentStage && stage.Status == "running" {
			indicator := fmt.Sprintf("%s   ⤷ %s\n", "\033[90m", "\033[0m")
			output.WriteString(indicator)
		}
	}
	
	// Write output
	fmt.Fprint(ms.writer, output.String())
	
	// Count lines in output for next clear
	ms.outputLineCount = strings.Count(output.String(), "\n")
	if ms.outputLineCount == 0 {
		ms.outputLineCount = 1
	}
}