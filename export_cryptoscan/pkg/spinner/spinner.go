package spinner

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Animation patterns
var (
	Line = []string{"|", "/", "-", "\\"}
	Dot  = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	Grow = []string{"▁", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃"}
	Moon = []string{"🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"}
	Lock = []string{"🔒", "🔓", "🔐", "🔏"}
)

// Style defines colors and formatting for the spinner
type Style struct {
	SymbolColor    string
	MessageColor   string
	SuccessSymbol  string
	SuccessColor   string
	WarningSymbol  string
	WarningColor   string
	ErrorSymbol    string
	ErrorColor     string
	PrefixTemplate string
}

// DefaultStyle returns the default spinner style with ANSI colors
func DefaultStyle() *Style {
	return &Style{
		SymbolColor:    "\033[36m", // Cyan
		MessageColor:   "\033[0m",  // Reset
		SuccessSymbol:  "✓",
		SuccessColor:   "\033[32m", // Green
		WarningSymbol:  "⚠",
		WarningColor:   "\033[33m", // Yellow
		ErrorSymbol:    "✗",
		ErrorColor:     "\033[31m", // Red
		PrefixTemplate: " %s ",
	}
}

// Spinner represents an animated spinner
type Spinner struct {
	message        string
	animation      []string
	style          *Style
	writer         io.Writer
	stopChan       chan struct{}
	doneWait       *sync.WaitGroup
	animationIndex int
	lastOutputLen  int
	interval       time.Duration
	active         bool
	mutex          *sync.Mutex
}

// New creates a new spinner with the given message
func New(message string, animation []string) *Spinner {
	return &Spinner{
		message:   message,
		animation: animation,
		style:     DefaultStyle(),
		writer:    os.Stdout,
		stopChan:  make(chan struct{}),
		doneWait:  &sync.WaitGroup{},
		interval:  100 * time.Millisecond,
		mutex:     &sync.Mutex{},
	}
}

// WithStyle sets a custom style for the spinner
func (s *Spinner) WithStyle(style *Style) *Spinner {
	s.style = style
	return s
}

// WithWriter sets a custom writer for the spinner output
func (s *Spinner) WithWriter(writer io.Writer) *Spinner {
	s.writer = writer
	return s
}

// WithInterval sets the animation interval
func (s *Spinner) WithInterval(interval time.Duration) *Spinner {
	s.interval = interval
	return s
}

// Start begins the spinner animation
func (s *Spinner) Start() *Spinner {
	s.mutex.Lock()
	if s.active {
		s.mutex.Unlock()
		return s
	}
	s.active = true
	s.mutex.Unlock()

	s.doneWait.Add(1)
	go func() {
		defer s.doneWait.Done()

		for {
			select {
			case <-s.stopChan:
				return
			default:
				s.mutex.Lock()
				s.erase()
				s.render()
				s.mutex.Unlock()
				time.Sleep(s.interval)
			}
		}
	}()

	return s
}

// Stop stops the spinner animation
func (s *Spinner) Stop() *Spinner {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.active {
		return s
	}

	s.active = false
	close(s.stopChan)
	s.doneWait.Wait()
	s.erase()
	
	// Reset spinner channel
	s.stopChan = make(chan struct{})

	return s
}

// UpdateMessage changes the spinner message
func (s *Spinner) UpdateMessage(message string) *Spinner {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.message = message
	if s.active {
		s.erase()
		s.render()
	}
	
	return s
}

// Success stops the spinner and displays a success message
func (s *Spinner) Success(message string) {
	s.Stop()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	symbol := s.style.SuccessSymbol
	symbolColor := s.style.SuccessColor
	messageColor := s.style.MessageColor
	
	output := fmt.Sprintf("%s%s%s %s%s\n", 
		symbolColor, 
		symbol, 
		"\033[0m", 
		messageColor, 
		message)
	
	fmt.Fprint(s.writer, output)
}

// Warning stops the spinner and displays a warning message
func (s *Spinner) Warning(message string) {
	s.Stop()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	symbol := s.style.WarningSymbol
	symbolColor := s.style.WarningColor
	messageColor := s.style.MessageColor
	
	output := fmt.Sprintf("%s%s%s %s%s\n", 
		symbolColor, 
		symbol, 
		"\033[0m", 
		messageColor, 
		message)
	
	fmt.Fprint(s.writer, output)
}

// Error stops the spinner and displays an error message
func (s *Spinner) Error(message string) {
	s.Stop()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	symbol := s.style.ErrorSymbol
	symbolColor := s.style.ErrorColor
	messageColor := s.style.MessageColor
	
	output := fmt.Sprintf("%s%s%s %s%s\n", 
		symbolColor, 
		symbol, 
		"\033[0m", 
		messageColor, 
		message)
	
	fmt.Fprint(s.writer, output)
}

// render draws the current frame of the spinner
func (s *Spinner) render() {
	if len(s.animation) == 0 {
		return
	}
	
	// Update animation frame
	s.animationIndex = (s.animationIndex + 1) % len(s.animation)
	symbol := s.animation[s.animationIndex]
	
	// Format the prefix with the symbol
	prefix := fmt.Sprintf(s.style.PrefixTemplate, fmt.Sprintf("%s%s%s", s.style.SymbolColor, symbol, "\033[0m"))
	
	// Create the full output
	output := fmt.Sprintf("%s%s%s", prefix, s.style.MessageColor, s.message)
	
	// Update last output length for erasing
	s.lastOutputLen = len(s.message) + len(prefix) - (len(s.style.SymbolColor) + len(s.style.MessageColor) + len("\033[0m"))
	
	// Write to output
	fmt.Fprint(s.writer, output)
}

// erase removes the current line of output
func (s *Spinner) erase() {
	if s.lastOutputLen > 0 {
		fmt.Fprint(s.writer, "\r"+strings.Repeat(" ", s.lastOutputLen)+"\r")
	}
}