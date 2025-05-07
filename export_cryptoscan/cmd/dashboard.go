package cmd

import (
        "fmt"
        "time"

        "github.com/spf13/cobra"
        "github.com/yourusername/cryptoscan/internal/git"
        "github.com/yourusername/cryptoscan/internal/reporter"
        "github.com/yourusername/cryptoscan/internal/scanner"
        "github.com/yourusername/cryptoscan/pkg/spinner"
)

var (
        dashboardCmd = &cobra.Command{
                Use:   "dashboard [github repository URL or local path]",
                Short: "Interactive dashboard for viewing cryptographic vulnerabilities",
                Long: `Display an interactive dashboard with color-coded risk levels and analytics
for cryptographic assets and vulnerabilities found in a repository or local path.

Examples:
  cryptoscan dashboard https://github.com/example/repo
  cryptoscan dashboard ./local/directory
  cryptoscan dashboard ./path/to/config.yml`,
                Args: cobra.ExactArgs(1),
                Run:  runDashboard,
        }
        
        refreshInterval int
)

func init() {
        dashboardCmd.Flags().IntVar(&refreshInterval, "refresh", 0, "Refresh interval in seconds (0 for no auto-refresh)")
}

func runDashboard(cmd *cobra.Command, args []string) {
        path := args[0]
        var repo *git.Repository
        var err error
        
        // Check if it's a GitHub URL or local path
        if isGitHubURL(path) {
                // It's a GitHub URL
                if verbose {
                        fmt.Printf("Cloning repository: %s\n", path)
                }
                
                // Clone repository
                repo, err = git.CloneRepository(path)
                if err != nil {
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
                        exitWithError("Failed to access local path", err)
                }
        }

        // Create scanner
        cryptoScanner := scanner.NewScanner(repo)
        
        // First display
        displayDashboard(cryptoScanner, path)
        
        // If refresh interval is set, keep refreshing
        if refreshInterval > 0 {
                for {
                        // Wait for the refresh interval
                        time.Sleep(time.Duration(refreshInterval) * time.Second)
                        
                        // Re-scan and display
                        displayDashboard(cryptoScanner, path)
                }
        }
}

func displayDashboard(cryptoScanner *scanner.Scanner, path string) {
        // Create spinner for scanning process
        spin := spinner.New("Scanning for cryptographic assets", spinner.Dot)
        
        // Only use spinner in non-verbose mode
        if !verbose {
                spin.Start()
        } else {
                fmt.Println("Scanning for cryptographic assets...")
        }
        
        // Scan for crypto assets
        findings, err := cryptoScanner.Scan()
        
        if !verbose {
                spin.Stop()
        }
        
        if err != nil {
                exitWithError("Failed to scan", err)
        }
        
        // Create spinner for vulnerability checking
        spin = spinner.New("Checking for vulnerabilities", spinner.Dot)
        
        // Only use spinner in non-verbose mode
        if !verbose {
                spin.Start()
        } else {
                fmt.Println("Checking for vulnerabilities...")
        }
        
        // Check for vulnerabilities
        err = cryptoScanner.CheckVulnerabilities(findings)
        
        if !verbose {
                spin.Stop()
        }
        
        if err != nil {
                exitWithError("Failed to check vulnerabilities", err)
        }
        
        // Create spinner for preparing dashboard
        spin = spinner.New("Preparing dashboard", spinner.Dot)
        if !verbose {
                spin.Start()
        }
        
        // Apply filters based on command-line options
        filteredFindings := applyFilters(findings)
        
        if !verbose {
                spin.Stop()
        }
        
        // Create and display dashboard
        dashboard := reporter.NewDashboard(filteredFindings, path)
        dashboard.Display()
}

func isGitHubURL(path string) bool {
        return startsWith(path, "https://github.com/") || startsWith(path, "git@github.com:")
}

func startsWith(s, prefix string) bool {
        if len(s) < len(prefix) {
                return false
        }
        return s[:len(prefix)] == prefix
}