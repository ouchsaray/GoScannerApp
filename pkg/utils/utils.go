package utils

import (
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ValidateGitHubURL validates if a URL is a valid GitHub repository URL
func ValidateGitHubURL(rawURL string) (string, error) {
	// Handle both HTTPS and SSH URL formats
	if strings.HasPrefix(rawURL, "git@github.com:") {
		// SSH format: git@github.com:owner/repo.git
		sshPattern := regexp.MustCompile(`^git@github\.com:([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)(\.git)?$`)
		if !sshPattern.MatchString(rawURL) {
			return "", ErrInvalidURL
		}
		
		// SSH URLs are already in the correct format for go-git
		return rawURL, nil
	}
	
	// HTTPS format: https://github.com/owner/repo
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", ErrInvalidURL
	}
	
	if parsedURL.Host != "github.com" {
		return "", ErrInvalidURL
	}
	
	// Remove .git extension if present
	path := parsedURL.Path
	if strings.HasSuffix(path, ".git") {
		path = path[:len(path)-4]
	}
	
	// Validate path format: /owner/repo
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", ErrInvalidURL
	}
	
	// Return the normalized URL
	return "https://github.com/" + parts[0] + "/" + parts[1], nil
}

// ErrInvalidURL is returned when the URL is not a valid GitHub repository URL
var ErrInvalidURL = &customError{"invalid GitHub repository URL"}

// TempDir creates a temporary directory and returns its path
func TempDir(prefix string) (string, error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", err
	}
	return dir, nil
}

// customError is a custom error type
type customError struct {
	message string
}

// Error returns the error message
func (e *customError) Error() string {
	return e.message
}
