package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
)

var (
        outputFormat string
        verbose      bool
        rootCmd      = &cobra.Command{
                Use:   "cryptoscan",
                Short: "Scans GitHub repositories for cryptographic assets and vulnerabilities",
                Long: `CryptoScan is a command-line tool that scans GitHub repositories
for cryptographic assets such as private keys, certificates, and cryptographic
implementations, and checks them for known vulnerabilities.`,
        }
)

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
        return rootCmd.Execute()
}

func init() {
        rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "Output format (text, json)")
        rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
        
        rootCmd.AddCommand(scanCmd)
        rootCmd.AddCommand(dashboardCmd)
}

// exitWithError prints the error message and exits with a non-zero code
func exitWithError(msg string, err error) {
        fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
        os.Exit(1)
}
