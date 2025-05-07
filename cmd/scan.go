package cmd

import (
        "fmt"
        "path/filepath"
        "strings"
        "time"

        "github.com/spf13/cobra"
        "github.com/yourusername/cryptoscan/internal/git"
        "github.com/yourusername/cryptoscan/internal/reporter"
        "github.com/yourusername/cryptoscan/internal/scanner"
        "github.com/yourusername/cryptoscan/pkg/spinner"
        "github.com/yourusername/cryptoscan/pkg/types"
)

var (
        scanCmd = &cobra.Command{
                Use:   "scan [repository URL or local path]",
                Short: "Scan a Git repository or local directory for cryptographic assets",
                Long: `Scan a Git repository or local directory for cryptographic assets and vulnerabilities.
Supported repository providers:
- GitHub: https://github.com/owner/repo
- GitLab: https://gitlab.com/owner/repo
- Bitbucket: https://bitbucket.org/owner/repo

For local files or directories, use a path like './directory' or '/path/to/file'.

Examples:
  cryptoscan scan https://github.com/example/repo
  cryptoscan scan https://gitlab.com/example/repo
  cryptoscan scan https://bitbucket.org/example/repo
  cryptoscan scan ./local/directory
  cryptoscan scan ./path/to/config.yml
  cryptoscan scan https://github.com/example/repo --skip-libs --severity HIGH
  cryptoscan scan ./directory --file-pattern "*.js" --only-vuln`,
                Args: cobra.ExactArgs(1),
                Run:  runScan,
        }
        tempDir       string
        skipVulnCheck bool
        skipLibraries bool
        onlyVulnerable bool
        severityFilter string
        fileFilter     string
        typeFilter     string
        maxResults     int
)

func init() {
        scanCmd.Flags().BoolVar(&skipVulnCheck, "skip-vuln", false, "Skip vulnerability check")
        scanCmd.Flags().BoolVar(&skipLibraries, "skip-libs", false, "Skip scanning libraries and vendor directories")
        scanCmd.Flags().BoolVar(&onlyVulnerable, "only-vuln", false, "Show only findings with vulnerabilities")
        scanCmd.Flags().StringVar(&severityFilter, "severity", "", "Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)")
        scanCmd.Flags().StringVar(&fileFilter, "file-pattern", "", "Filter files by pattern (e.g., '*.js' or 'src/*')")
        scanCmd.Flags().StringVar(&typeFilter, "type", "", "Filter by finding type (e.g., 'Private Key' or 'AWS')")
        scanCmd.Flags().IntVar(&maxResults, "max", 0, "Maximum number of results to show (0 for all)")
}

func runScan(cmd *cobra.Command, args []string) {
        path := args[0]
        var repo *git.Repository
        var err error
        
        // Setup multispinner for progress display
        stages := []string{
                "Preparing repository",
                "Scanning for cryptographic assets",
                "Checking for vulnerabilities",
                "Analyzing findings",
                "Generating report",
        }
        spinnerAnimation := spinner.Dot
        multiSpinner := spinner.NewMulti(stages, spinnerAnimation)
        
        // Don't show spinner in verbose mode
        if !verbose {
                multiSpinner.Start()
                defer multiSpinner.Stop()
        }
        
        // Check if it's a Git repository URL or local path
        multiSpinner.StartStage(0)
        provider := git.DetectProvider(path)
        
        if provider != git.ProviderUnknown {
                // It's a Git repository URL
                if verbose {
                        fmt.Printf("Cloning %s repository: %s\n", provider, path)
                }
                
                // Clone repository
                repo, err = git.CloneRepository(path)
                if err != nil {
                        multiSpinner.ErrorStage(0)
                        if !verbose {
                                multiSpinner.Stop()
                        }
                        exitWithError("Failed to clone repository", err)
                }
                defer repo.Cleanup()
        } else {
                // It's a local path
                if verbose {
                        fmt.Printf("Scanning local path: %s\n", path)
                }
                
                // Create a local repository
                repo, err = git.NewLocalRepository(path)
                if err != nil {
                        multiSpinner.ErrorStage(0)
                        if !verbose {
                                multiSpinner.Stop()
                        }
                        exitWithError("Failed to access local path", err)
                }
                
                // If provider was detected from local git config, show it
                if repo.Provider != git.ProviderUnknown && verbose {
                        fmt.Printf("Detected %s repository\n", repo.Provider)
                }
        }
        multiSpinner.SuccessStage(0)

        // Create scanner
        cryptoScanner := scanner.NewScanner(repo)
        
        // Scan for crypto assets
        multiSpinner.StartStage(1)
        if verbose {
                fmt.Println("Scanning for cryptographic assets...")
        }
        
        scanStartTime := time.Now()
        findings, err := cryptoScanner.Scan()
        scanDuration := time.Since(scanStartTime)
        
        if err != nil {
                multiSpinner.ErrorStage(1)
                if !verbose {
                        multiSpinner.Stop()
                }
                exitWithError("Failed to scan", err)
        }
        multiSpinner.SuccessStage(1)
        
        // Check for vulnerabilities if not skipped
        multiSpinner.StartStage(2)
        if !skipVulnCheck {
                if verbose {
                        fmt.Println("Checking for vulnerabilities...")
                }
                
                vulnStartTime := time.Now()
                err = cryptoScanner.CheckVulnerabilities(findings)
                vulnDuration := time.Since(vulnStartTime)
                
                if err != nil {
                        multiSpinner.ErrorStage(2)
                        if !verbose {
                                multiSpinner.Stop()
                        }
                        exitWithError("Failed to check vulnerabilities", err)
                }
                
                if verbose {
                        fmt.Printf("Vulnerability check completed in %.2f seconds\n", vulnDuration.Seconds())
                }
        } else {
                if verbose {
                        fmt.Println("Vulnerability check skipped")
                }
        }
        multiSpinner.SuccessStage(2)
        
        // Apply filters based on command-line options
        multiSpinner.StartStage(3)
        if verbose {
                fmt.Println("Analyzing findings and applying filters...")
        }
        
        filteredFindings := applyFilters(findings)
        multiSpinner.SuccessStage(3)
        
        // Generate report
        multiSpinner.StartStage(4)
        if verbose {
                fmt.Println("Generating report...")
        }
        
        r := reporter.NewReporter(outputFormat)
        output, err := r.Generate(filteredFindings)
        if err != nil {
                multiSpinner.ErrorStage(4)
                if !verbose {
                        multiSpinner.Stop()
                }
                exitWithError("Failed to generate report", err)
        }
        multiSpinner.SuccessStage(4)
        
        // Stop spinner before printing output
        if !verbose {
                multiSpinner.Stop()
        }
        
        // Print performance summary in verbose mode
        if verbose {
                // Safely get file list
                files, _ := repo.ListFiles()
                
                fmt.Printf("\n=== Performance Summary ===\n")
                fmt.Printf("Total scan time: %.2f seconds\n", scanDuration.Seconds())
                fmt.Printf("Files processed: %d\n", len(files))
                fmt.Printf("Findings: %d (filtered: %d)\n", len(findings), len(filteredFindings))
                fmt.Printf("=========================\n\n")
        }
        
        // Print report
        fmt.Println(output)
}

// applyFilters applies command-line filters to findings
func applyFilters(findings []types.Finding) []types.Finding {
        var filtered []types.Finding
        
        for _, finding := range findings {
                // Skip based on library paths if requested
                if skipLibraries {
                        skipPaths := []string{"/vendor/", "/node_modules/", "/deps/", "/lib/", "/third_party/"}
                        skip := false
                        for _, path := range skipPaths {
                                if strings.Contains(finding.File, path) {
                                        skip = true
                                        break
                                }
                        }
                        if skip {
                                continue
                        }
                }
                
                // Filter by vulnerability if requested
                if onlyVulnerable && !finding.Vulnerable {
                        continue
                }
                
                // Filter by severity
                if severityFilter != "" {
                        if !isAtLeastSeverity(finding.Severity, severityFilter) {
                                continue
                        }
                }
                
                // Filter by file pattern
                if fileFilter != "" {
                        matched, err := filepath.Match(fileFilter, filepath.Base(finding.File))
                        if err != nil || !matched {
                                continue
                        }
                }
                
                // Filter by finding type
                if typeFilter != "" && !strings.Contains(finding.Type, typeFilter) {
                        continue
                }
                
                filtered = append(filtered, finding)
        }
        
        // Apply max results limit if specified
        if maxResults > 0 && len(filtered) > maxResults {
                filtered = filtered[:maxResults]
        }
        
        return filtered
}

// isAtLeastSeverity checks if a severity level is at least the minimum specified
func isAtLeastSeverity(severity, minimum string) bool {
        severityRanks := map[string]int{
                "CRITICAL": 4,
                "HIGH":     3,
                "MEDIUM":   2,
                "LOW":      1,
                "INFO":     0,
        }
        
        // Normalize case
        severity = strings.ToUpper(severity)
        minimum = strings.ToUpper(minimum)
        
        // Check severity rank
        return severityRanks[severity] >= severityRanks[minimum]
}