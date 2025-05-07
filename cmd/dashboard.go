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
                Use:   "dashboard [repository URL or local path]",
                Short: "Interactive dashboard for viewing cryptographic vulnerabilities",
                Long: `Display an interactive dashboard with color-coded risk levels and analytics
for cryptographic assets and vulnerabilities found in a repository or local path.

Supported repository providers:
- GitHub: https://github.com/owner/repo
- GitLab: https://gitlab.com/owner/repo
- Bitbucket: https://bitbucket.org/owner/repo

Examples:
  cryptoscan dashboard https://github.com/example/repo
  cryptoscan dashboard https://gitlab.com/example/repo
  cryptoscan dashboard https://bitbucket.org/example/repo
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
        
        // Check if it's a Git repository URL or local path
        provider := git.DetectProvider(path)
        
        if provider != git.ProviderUnknown {
                // It's a Git repository URL
                if verbose {
                        fmt.Printf("Cloning %s repository: %s\n", provider, path)
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
                
                // If provider was detected from local git config, show it
                if repo.Provider != git.ProviderUnknown && verbose {
                        fmt.Printf("Detected %s repository\n", repo.Provider)
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
        // Pass provider information if available
        providerString := ""
        if cryptoScanner.GetRepository().Provider != "" {
                providerString = string(cryptoScanner.GetRepository().Provider)
        }
        dashboard := reporter.NewDashboard(filteredFindings, path, providerString)
        dashboard.Display()
}

// These functions are replaced by git.DetectProvider