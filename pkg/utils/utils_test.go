package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestFormatDuration tests the FormatDuration function
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "Less than a second",
			duration: 500 * time.Millisecond,
			expected: "0.5s",
		},
		{
			name:     "One second",
			duration: 1 * time.Second,
			expected: "1.0s",
		},
		{
			name:     "Multiple seconds",
			duration: 5*time.Second + 500*time.Millisecond,
			expected: "5.5s",
		},
		{
			name:     "One minute",
			duration: 1 * time.Minute,
			expected: "1m 0.0s",
		},
		{
			name:     "Minutes and seconds",
			duration: 2*time.Minute + 30*time.Second,
			expected: "2m 30.0s",
		},
		{
			name:     "Zero duration",
			duration: 0,
			expected: "0.0s",
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := FormatDuration(tc.duration)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestContainsString tests the ContainsString function
func TestContainsString(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		str      string
		expected bool
	}{
		{
			name:     "String exists in slice",
			slice:    []string{"apple", "banana", "cherry"},
			str:      "banana",
			expected: true,
		},
		{
			name:     "String does not exist in slice",
			slice:    []string{"apple", "banana", "cherry"},
			str:      "orange",
			expected: false,
		},
		{
			name:     "Empty slice",
			slice:    []string{},
			str:      "apple",
			expected: false,
		},
		{
			name:     "Nil slice",
			slice:    nil,
			str:      "apple",
			expected: false,
		},
		{
			name:     "Empty string",
			slice:    []string{"apple", "banana", "cherry"},
			str:      "",
			expected: false,
		},
		{
			name:     "Case sensitivity",
			slice:    []string{"Apple", "Banana", "Cherry"},
			str:      "apple",
			expected: false,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ContainsString(tc.slice, tc.str)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestTruncateString tests the TruncateString function
func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		str      string
		length   int
		expected string
	}{
		{
			name:     "String shorter than length",
			str:      "Hello",
			length:   10,
			expected: "Hello",
		},
		{
			name:     "String equal to length",
			str:      "Hello",
			length:   5,
			expected: "Hello",
		},
		{
			name:     "String longer than length",
			str:      "Hello, World!",
			length:   5,
			expected: "He...",
		},
		{
			name:     "Empty string",
			str:      "",
			length:   5,
			expected: "",
		},
		{
			name:     "Length zero",
			str:      "Hello",
			length:   0,
			expected: "...",
		},
		{
			name:     "Length negative",
			str:      "Hello",
			length:   -5,
			expected: "...",
		},
		{
			name:     "Length less than ellipsis",
			str:      "Hello",
			length:   2,
			expected: "..",
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := TruncateString(tc.str, tc.length)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestGetSeverityColor tests the GetSeverityColor function
func TestGetSeverityColor(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected string
	}{
		{
			name:     "CRITICAL severity",
			severity: "CRITICAL",
			expected: "31", // Red
		},
		{
			name:     "HIGH severity",
			severity: "HIGH",
			expected: "31", // Red
		},
		{
			name:     "MEDIUM severity",
			severity: "MEDIUM",
			expected: "33", // Yellow
		},
		{
			name:     "LOW severity",
			severity: "LOW",
			expected: "32", // Green
		},
		{
			name:     "Unknown severity",
			severity: "UNKNOWN",
			expected: "0", // Default/Reset
		},
		{
			name:     "Empty severity",
			severity: "",
			expected: "0", // Default/Reset
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GetSeverityColor(tc.severity)
			assert.Contains(t, result, tc.expected)
		})
	}
}

// TestGetPathWithoutExtension tests the GetPathWithoutExtension function
func TestGetPathWithoutExtension(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "File with extension",
			path:     "file.txt",
			expected: "file",
		},
		{
			name:     "File with multiple dots",
			path:     "file.tar.gz",
			expected: "file.tar",
		},
		{
			name:     "File without extension",
			path:     "file",
			expected: "file",
		},
		{
			name:     "Path with directory and extension",
			path:     "/path/to/file.txt",
			expected: "/path/to/file",
		},
		{
			name:     "Path with directory and no extension",
			path:     "/path/to/file",
			expected: "/path/to/file",
		},
		{
			name:     "Hidden file",
			path:     ".gitignore",
			expected: ".gitignore",
		},
		{
			name:     "Empty path",
			path:     "",
			expected: "",
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GetPathWithoutExtension(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}