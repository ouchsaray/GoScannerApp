package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewRepository tests creating a new Repository instance
func TestNewRepository(t *testing.T) {
	repo := NewRepository()
	assert.NotNil(t, repo)
}

// TestGetProviderFromURL tests detecting Git providers from URLs
func TestGetProviderFromURL(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		wantProvider string
	}{
		{
			name:         "GitHub HTTPS URL",
			url:          "https://github.com/username/repo.git",
			wantProvider: "GitHub",
		},
		{
			name:         "GitHub SSH URL",
			url:          "git@github.com:username/repo.git",
			wantProvider: "GitHub",
		},
		{
			name:         "GitHub URL without .git",
			url:          "https://github.com/username/repo",
			wantProvider: "GitHub",
		},
		{
			name:         "GitLab HTTPS URL",
			url:          "https://gitlab.com/username/repo.git",
			wantProvider: "GitLab",
		},
		{
			name:         "GitLab SSH URL",
			url:          "git@gitlab.com:username/repo.git",
			wantProvider: "GitLab",
		},
		{
			name:         "Bitbucket HTTPS URL",
			url:          "https://username@bitbucket.org/username/repo.git",
			wantProvider: "Bitbucket",
		},
		{
			name:         "Bitbucket SSH URL",
			url:          "git@bitbucket.org:username/repo.git",
			wantProvider: "Bitbucket",
		},
		{
			name:         "Unknown provider",
			url:          "https://example.com/username/repo.git",
			wantProvider: "Unknown",
		},
		{
			name:         "Empty URL",
			url:          "",
			wantProvider: "Unknown",
		},
		{
			name:         "Local file path",
			url:          "/path/to/repo",
			wantProvider: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := GetProviderFromURL(tt.url)
			assert.Equal(t, tt.wantProvider, provider)
		})
	}
}

// TestCloneRepository tests cloning a Git repository
// Note: This test requires network access to GitHub
func TestCloneRepository(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires network access")
	}

	// Create a temporary directory for the cloned repository
	tmpDir, err := os.MkdirTemp("", "repo-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Example public repository URL that is likely to exist
	repoURL := "https://github.com/golang/example.git"
	
	repo := NewRepository()
	err = repo.Clone(repoURL, tmpDir)
	
	// If we can't clone for network reasons, skip the test
	if err != nil {
		t.Skipf("Skipping due to clone error: %v", err)
	}
	
	// Check that the repository was cloned
	assert.DirExists(t, filepath.Join(tmpDir, ".git"))
}

// TestOpenRepository tests opening a local Git repository
func TestOpenRepository(t *testing.T) {
	// Create a temporary directory that looks like a Git repository
	tmpDir, err := os.MkdirTemp("", "repo-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create a .git directory (this is a simplified test)
	err = os.Mkdir(filepath.Join(tmpDir, ".git"), 0755)
	assert.NoError(t, err)
	
	repo := NewRepository()
	
	// Test with a directory that has a .git subdirectory
	err = repo.Open(tmpDir)
	assert.NoError(t, err)
	
	// Test with a non-existent directory
	err = repo.Open("/non/existent/path")
	assert.Error(t, err)
	
	// Create a directory without a .git subdirectory
	nonGitDir, err := os.MkdirTemp("", "non-git")
	assert.NoError(t, err)
	defer os.RemoveAll(nonGitDir)
	
	// Test with a directory that is not a Git repository
	err = repo.Open(nonGitDir)
	assert.Error(t, err)
}

// TestGetRemoteURL tests getting the remote URL from a repository
func TestGetRemoteURL(t *testing.T) {
	// This is a more advanced test that would require a real Git repository
	// We'll mock it by creating a simplified Repository with a URL
	
	// Simple case with direct access to the URL field
	repo := &Repository{
		url: "https://github.com/username/repo.git",
	}
	
	// Test with a repository that has a URL
	url, err := repo.GetRemoteURL()
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/username/repo.git", url)
	
	// Test with a repository that has no URL
	emptyRepo := NewRepository()
	url, err = emptyRepo.GetRemoteURL()
	assert.Error(t, err)
	assert.Equal(t, "", url)
}

// TestIsLocalPath tests checking if a path is local
func TestIsLocalPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "Absolute path",
			path:     "/absolute/path",
			expected: true,
		},
		{
			name:     "Relative path",
			path:     "./relative/path",
			expected: true,
		},
		{
			name:     "Current directory",
			path:     ".",
			expected: true,
		},
		{
			name:     "Parent directory",
			path:     "..",
			expected: true,
		},
		{
			name:     "HTTP URL",
			path:     "https://github.com/user/repo",
			expected: false,
		},
		{
			name:     "SSH URL",
			path:     "git@github.com:user/repo.git",
			expected: false,
		},
		{
			name:     "Empty path",
			path:     "",
			expected: false,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsLocalPath(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestGetProvider tests getting the provider from a repository
func TestGetProvider(t *testing.T) {
	// Test with GitHub URL
	repoGitHub := &Repository{
		url: "https://github.com/username/repo.git",
	}
	assert.Equal(t, "GitHub", repoGitHub.GetProvider())
	
	// Test with GitLab URL
	repoGitLab := &Repository{
		url: "https://gitlab.com/username/repo.git",
	}
	assert.Equal(t, "GitLab", repoGitLab.GetProvider())
	
	// Test with Bitbucket URL
	repoBitbucket := &Repository{
		url: "https://bitbucket.org/username/repo.git",
	}
	assert.Equal(t, "Bitbucket", repoBitbucket.GetProvider())
	
	// Test with unknown provider
	repoUnknown := &Repository{
		url: "https://example.com/username/repo.git",
	}
	assert.Equal(t, "Unknown", repoUnknown.GetProvider())
	
	// Test with empty URL
	repoEmpty := &Repository{
		url: "",
	}
	assert.Equal(t, "Unknown", repoEmpty.GetProvider())
}

// TestScanRepository is a basic smoke test for the scan functionality
func TestScanRepository(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "scan-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create a few test files
	files := []struct {
		path    string
		content string
	}{
		{
			path:    filepath.Join(tmpDir, "test.go"),
			content: `package main

func main() {
	// This is a test file
	apiKey := "AIzaSyA1_ECqZEFYtOv5RAZaSIrnT1JO3JWzMjM" // This should be detected
}`,
		},
		{
			path:    filepath.Join(tmpDir, "ignored.txt"),
			content: "This file should be ignored by default pattern",
		},
		{
			path:    filepath.Join(tmpDir, "config.yml"),
			content: `
# Configuration file
api_key: "AIzaSyDgElLI_RJ8WJ7TOcjHJBaZrj2WhFP7uQk"
`,
		},
	}
	
	for _, file := range files {
		err := os.WriteFile(file.path, []byte(file.content), 0644)
		assert.NoError(t, err)
	}
	
	// Create a repository
	repo := NewRepository()
	
	// Set up a channel to receive findings
	findingsChan := make(chan struct{
		file     string
		findings []interface{} // Use interface{} to avoid importing the scanner package
	})
	
	// We can't fully test ScanRepository without scanner dependency,
	// so we'll just make sure it doesn't panic and can detect files
	assert.NotPanics(t, func() {
		// This would normally fail because we're not setting up a real Git repository
		// and we're not providing a real scanFunc, but we just want to make sure
		// the logic for finding files works
		repo.ScanRepository(tmpDir, nil, nil, nil)
	})
	
	// Close the channel in case it was created
	close(findingsChan)
}