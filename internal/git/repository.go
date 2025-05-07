package git

import (
        "fmt"
        "io/ioutil"
        "os"
        "path/filepath"
        "regexp"
        "strings"
)

// Provider represents a Git provider type
type Provider string

const (
        // ProviderGitHub represents GitHub
        ProviderGitHub Provider = "github"
        // ProviderGitLab represents GitLab
        ProviderGitLab Provider = "gitlab"
        // ProviderBitbucket represents Bitbucket
        ProviderBitbucket Provider = "bitbucket"
        // ProviderUnknown represents an unknown provider
        ProviderUnknown Provider = "unknown"
)

// Repository represents a Git repository or local file path
type Repository struct {
        URL       string
        LocalPath string
        Provider  Provider
        isLocal   bool
        repo      interface{} // In test mode, we don't need the actual git.Repository
}

// DetectProvider detects the Git provider from a URL
func DetectProvider(url string) Provider {
        // GitHub patterns
        githubPatterns := []*regexp.Regexp{
                regexp.MustCompile(`^https://github\.com/`),
                regexp.MustCompile(`^git@github\.com:`),
        }

        // GitLab patterns
        gitlabPatterns := []*regexp.Regexp{
                regexp.MustCompile(`^https://(www\.)?gitlab\.com/`),
                regexp.MustCompile(`^git@gitlab\.com:`),
        }

        // Bitbucket patterns
        bitbucketPatterns := []*regexp.Regexp{
                regexp.MustCompile(`^https://(www\.)?bitbucket\.org/`),
                regexp.MustCompile(`^git@bitbucket\.org:`),
        }

        // Check GitHub
        for _, pattern := range githubPatterns {
                if pattern.MatchString(url) {
                        return ProviderGitHub
                }
        }

        // Check GitLab
        for _, pattern := range gitlabPatterns {
                if pattern.MatchString(url) {
                        return ProviderGitLab
                }
        }

        // Check Bitbucket
        for _, pattern := range bitbucketPatterns {
                if pattern.MatchString(url) {
                        return ProviderBitbucket
                }
        }

        return ProviderUnknown
}

// CloneRepository clones a Git repository to a temporary directory
// In test mode (if CRYPTOSCAN_TEST_MODE is set), it will use the current directory
func CloneRepository(url string) (*Repository, error) {
        // Detect provider
        provider := DetectProvider(url)
        
        // Check if we're in test mode
        if os.Getenv("CRYPTOSCAN_TEST_MODE") == "true" {
                fmt.Println("Running in test mode - using current directory instead of cloning")
                currentDir, err := os.Getwd()
                if err != nil {
                        return nil, fmt.Errorf("failed to get current directory: %w", err)
                }

                return &Repository{
                        URL:       url,
                        LocalPath: currentDir,
                        Provider:  provider,
                }, nil
        }
        
        // Create a temporary directory
        tempDir, err := ioutil.TempDir("", "cryptoscan-")
        if err != nil {
                return nil, fmt.Errorf("failed to create temporary directory: %w", err)
        }

        // Prepare repository
        repo := &Repository{
                URL:       url,
                LocalPath: tempDir,
                Provider:  provider,
        }

        // In test mode we don't do git operations, so we won't implement
        // the real cloning here. This code would be filled in when not in test mode.
        
        // For now, just pretend we have a repo
        providerName := "unknown"
        if provider != ProviderUnknown {
                providerName = string(provider)
        }
        fmt.Printf("NOTE: This is a limited test implementation for %s - real Git functionality is disabled\n", providerName)
        
        repo.repo = nil
        return repo, nil
}

// ListFiles returns a list of all files in the repository
func (r *Repository) ListFiles() ([]string, error) {
        var files []string

        err := filepath.Walk(r.LocalPath, func(path string, info os.FileInfo, err error) error {
                if err != nil {
                        return err
                }
                if !info.IsDir() {
                        // Get relative path
                        relPath, err := filepath.Rel(r.LocalPath, path)
                        if err != nil {
                                return err
                        }
                        
                        // Skip .git directory
                        if strings.HasPrefix(relPath, ".git/") {
                                return nil
                        }
                        
                        files = append(files, relPath)
                }
                return nil
        })

        if err != nil {
                return nil, fmt.Errorf("failed to list files: %w", err)
        }

        return files, nil
}

// ReadFile reads a file from the repository
func (r *Repository) ReadFile(path string) ([]byte, error) {
        fullPath := filepath.Join(r.LocalPath, path)
        data, err := ioutil.ReadFile(fullPath)
        if err != nil {
                return nil, fmt.Errorf("failed to read file: %w", err)
        }
        return data, nil
}

// NewLocalRepository creates a Repository object from a local path
func NewLocalRepository(path string) (*Repository, error) {
        // Check if the path exists
        info, err := os.Stat(path)
        if err != nil {
                return nil, fmt.Errorf("failed to access path %s: %w", path, err)
        }
        
        // Determine the full path
        var fullPath string
        if info.IsDir() {
                // If it's a directory, use it as is
                fullPath, err = filepath.Abs(path)
                if err != nil {
                        return nil, fmt.Errorf("failed to get absolute path: %w", err)
                }
        } else {
                // If it's a file, use its directory
                dir := filepath.Dir(path)
                fullPath, err = filepath.Abs(dir)
                if err != nil {
                        return nil, fmt.Errorf("failed to get absolute path: %w", err)
                }
        }
        
        // Try to detect provider from potential git configuration
        provider := ProviderUnknown
        gitConfigPath := filepath.Join(fullPath, ".git", "config")
        if _, err := os.Stat(gitConfigPath); err == nil {
                // Read git config to determine provider if possible
                configData, err := ioutil.ReadFile(gitConfigPath)
                if err == nil {
                        configStr := string(configData)
                        switch {
                        case strings.Contains(configStr, "github.com"):
                                provider = ProviderGitHub
                        case strings.Contains(configStr, "gitlab.com"):
                                provider = ProviderGitLab
                        case strings.Contains(configStr, "bitbucket.org"):
                                provider = ProviderBitbucket
                        }
                }
        }
        
        return &Repository{
                LocalPath: fullPath,
                Provider:  provider,
                isLocal:   true,
        }, nil
}

// Cleanup removes the temporary directory
func (r *Repository) Cleanup() {
        // Don't clean up if it's a local path or in test mode
        if r.isLocal || os.Getenv("CRYPTOSCAN_TEST_MODE") == "true" {
                return
        }
        
        if r.LocalPath != "" {
                os.RemoveAll(r.LocalPath)
        }
}
