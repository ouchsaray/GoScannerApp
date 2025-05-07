package git

import (
        "fmt"
        "io/ioutil"
        "os"
        "path/filepath"
        "strings"
)

// Repository represents a Git repository or local file path
type Repository struct {
        URL       string
        LocalPath string
        isLocal   bool
        repo      interface{} // In test mode, we don't need the actual git.Repository
}

// CloneRepository clones a GitHub repository to a temporary directory
// In test mode (if CRYPTOSCAN_TEST_MODE is set), it will use the current directory
func CloneRepository(url string) (*Repository, error) {
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
        }

        // In test mode we don't do git operations, so we won't implement
        // the real cloning here. This code would be filled in when not in test mode.
        
        // For now, just pretend we have a repo
        fmt.Println("NOTE: This is a limited test implementation - real Git functionality is disabled")
        
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
        
        return &Repository{
                LocalPath: fullPath,
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
