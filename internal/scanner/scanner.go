package scanner

import (
        "fmt"
        "path/filepath"
        "sync"

        "github.com/yourusername/cryptoscan/internal/git"
        "github.com/yourusername/cryptoscan/pkg/types"
)

// Scanner represents a crypto asset scanner
type Scanner struct {
        repo     *git.Repository
        detector *Detector
}

// NewScanner creates a new scanner
func NewScanner(repo *git.Repository) *Scanner {
        return &Scanner{
                repo:     repo,
                detector: NewDetector(),
        }
}

// GetRepository returns the Git repository being scanned
func (s *Scanner) GetRepository() *git.Repository {
        return s.repo
}

// Scan scans the repository for cryptographic assets
func (s *Scanner) Scan() ([]types.Finding, error) {
        var findings []types.Finding
        var mutex sync.Mutex
        var wg sync.WaitGroup

        // Get list of files
        files, err := s.repo.ListFiles()
        if err != nil {
                return nil, fmt.Errorf("failed to list files: %w", err)
        }

        // Process each file
        workers := 10 // Number of parallel workers
        fileChan := make(chan string, len(files))

        // Start workers
        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for file := range fileChan {
                                // Skip binary files and large files
                                if isBinaryOrLargeFile(file) {
                                        continue
                                }

                                // Read file content
                                content, err := s.repo.ReadFile(file)
                                if err != nil {
                                        fmt.Printf("Warning: Failed to read file %s: %v\n", file, err)
                                        continue
                                }

                                // Detect crypto assets
                                fileFindings, err := s.detector.Detect(file, content)
                                if err != nil {
                                        fmt.Printf("Warning: Failed to scan file %s: %v\n", file, err)
                                        continue
                                }

                                // Add findings
                                if len(fileFindings) > 0 {
                                        mutex.Lock()
                                        findings = append(findings, fileFindings...)
                                        mutex.Unlock()
                                }
                        }
                }()
        }

        // Send files to workers
        for _, file := range files {
                fileChan <- file
        }
        close(fileChan)

        // Wait for all workers to finish
        wg.Wait()

        return findings, nil
}

// CheckVulnerabilities checks the found crypto assets for vulnerabilities
func (s *Scanner) CheckVulnerabilities(findings []types.Finding) error {
        for i := range findings {
                vulns := CheckVulnerabilities(findings[i])
                findings[i].Vulnerabilities = vulns
                
                if len(vulns) > 0 {
                        findings[i].Vulnerable = true
                        
                        // Set severity based on highest vulnerability severity
                        highestSeverity := "LOW"
                        for _, vuln := range vulns {
                                switch vuln.Severity {
                                case "CRITICAL":
                                        highestSeverity = "CRITICAL"
                                        break // Found highest possible severity, no need to check others
                                case "HIGH":
                                        if highestSeverity != "CRITICAL" {
                                                highestSeverity = "HIGH"
                                        }
                                case "MEDIUM":
                                        if highestSeverity != "CRITICAL" && highestSeverity != "HIGH" {
                                                highestSeverity = "MEDIUM"
                                        }
                                }
                                // If only LOW severities exist, highestSeverity will remain "LOW"
                        }
                        
                        findings[i].Severity = highestSeverity
                }
        }
        return nil
}

// isBinaryOrLargeFile checks if a file is likely binary or too large to process
func isBinaryOrLargeFile(path string) bool {
        // Skip known binary extensions
        ext := filepath.Ext(path)
        binaryExts := map[string]bool{
                ".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
                ".pdf": true, ".bin": true, ".exe": true, ".dll": true,
                ".so": true, ".zip": true, ".tar": true, ".gz": true,
                ".jar": true, ".class": true,
        }

        if binaryExts[ext] {
                return true
        }

        return false
}
