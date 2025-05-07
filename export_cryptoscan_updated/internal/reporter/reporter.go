package reporter

import (
        "encoding/json"
        "fmt"
        "sort"
        "strings"

        "github.com/yourusername/cryptoscan/pkg/types"
)

// Reporter generates reports from findings
type Reporter struct {
        format string
}

// NewReporter creates a new reporter
func NewReporter(format string) *Reporter {
        return &Reporter{
                format: format,
        }
}

// Generate creates a report from findings
func (r *Reporter) Generate(findings []types.Finding) (string, error) {
        if len(findings) == 0 {
                return "No cryptographic assets or vulnerabilities found.", nil
        }

        // Filter out false positives and known benign findings
        filteredFindings := r.filterFalsePositives(findings)
        if len(filteredFindings) == 0 {
                return "No significant cryptographic assets or vulnerabilities found after filtering.", nil
        }

        // Sort findings by severity and then by file path
        sort.Slice(filteredFindings, func(i, j int) bool {
                if filteredFindings[i].Severity != filteredFindings[j].Severity {
                        return severityRank(filteredFindings[i].Severity) > severityRank(filteredFindings[j].Severity)
                }
                return filteredFindings[i].File < filteredFindings[j].File
        })

        // Generate report based on format
        switch r.format {
        case "json":
                return r.generateJSON(filteredFindings)
        case "text", "":
                return r.generateText(filteredFindings)
        default:
                return "", fmt.Errorf("unsupported format: %s", r.format)
        }
}

// filterFalsePositives removes known false positives and categorizes findings
func (r *Reporter) filterFalsePositives(findings []types.Finding) []types.Finding {
        var filtered []types.Finding
        
        // Define common paths to ignore (e.g., caches, test files, examples)
        ignorePaths := []string{
                ".git/", 
                "node_modules/", 
                "/tmp/",
                "vendor/",
        }
        
        // Define common files to ignore
        ignoreFiles := []string{
                "go.sum",
                "package-lock.json",
                "yarn.lock",
                "Cargo.lock",
        }
        
        // Set to track file paths to avoid duplicates
        processedFiles := make(map[string]bool)
        
        for _, finding := range findings {
                // Skip if we've already processed a finding from this file with the same type
                fileTypeKey := finding.File + "|" + finding.Type
                if processedFiles[fileTypeKey] {
                        continue
                }
                
                // Check if file should be ignored based on path
                skipFile := false
                for _, ignorePath := range ignorePaths {
                        if strings.Contains(finding.File, ignorePath) {
                                skipFile = true
                                break
                        }
                }
                if skipFile {
                        continue
                }
                
                // Check if file should be ignored based on filename
                for _, ignoreFile := range ignoreFiles {
                        if strings.HasSuffix(finding.File, ignoreFile) {
                                skipFile = true
                                break
                        }
                }
                if skipFile {
                        continue
                }
                
                // Skip findings that are likely false positives
                if r.isLikelyFalsePositive(finding) {
                        continue
                }
                
                // Mark as processed
                processedFiles[fileTypeKey] = true
                
                // Add to filtered list
                filtered = append(filtered, finding)
        }
        
        return filtered
}

// isLikelyFalsePositive checks if a finding is likely a false positive
func (r *Reporter) isLikelyFalsePositive(finding types.Finding) bool {
        // Special case for detector.go which contains patterns as examples, not real keys
        if finding.File == "internal/scanner/detector.go" && 
           (strings.Contains(finding.Type, "Key") || 
            strings.Contains(finding.Type, "Certificate") || 
            strings.Contains(finding.Type, "PGP")) {
            // These are pattern definitions in the detector, not actual keys
            return true
        }
        
        // Skip potential encoded keys in compiled binaries or non-text files
        if finding.Type == "Potential Encoded Key" {
                // Skip if the content looks like a common package path or known binary pattern
                commonFalsePositives := []string{
                        "/com/",
                        "/org/",
                        "/nix/",
                        "/usr/",
                        "/go/",
                        "github.com",
                        "golang.org",
                        "cryptoscan/internal",
                        "yourusername",
                }
                
                for _, pattern := range commonFalsePositives {
                        if strings.Contains(finding.Content, pattern) {
                                return true
                        }
                }
        }
        
        // Skip certificates in CA stores or well-known locations
        if finding.Type == "Certificate" {
                commonCertPaths := []string{
                        "/ca-certificates/",
                        "/certs/",
                        "/ssl/certs/",
                }
                
                for _, path := range commonCertPaths {
                        if strings.Contains(finding.File, path) {
                                return true
                        }
                }
        }

        // Skip literal regex patterns in our source code
        if strings.Contains(finding.File, ".go") {
                patternIndicators := []string{
                        "regexp.MustCompile",
                        "case ",
                        "switch ",
                        "// ",
                        "/* ",
                }
                
                for _, indicator := range patternIndicators {
                        if strings.Contains(finding.Content, indicator) {
                                return true
                        }
                }
        }
        
        return false
}

// generateText creates a text report
func (r *Reporter) generateText(findings []types.Finding) (string, error) {
        var sb strings.Builder
        
        sb.WriteString("=== CryptoScan Findings ===\n\n")
        
        // Count vulnerabilities by severity
        criticalCount := 0
        highCount := 0
        mediumCount := 0
        lowCount := 0
        
        for _, finding := range findings {
                switch finding.Severity {
                case "CRITICAL":
                        criticalCount++
                case "HIGH":
                        highCount++
                case "MEDIUM":
                        mediumCount++
                case "LOW":
                        lowCount++
                }
        }
        
        // Write summary
        sb.WriteString("Summary:\n")
        sb.WriteString(fmt.Sprintf("- Critical: %d\n", criticalCount))
        sb.WriteString(fmt.Sprintf("- High: %d\n", highCount))
        sb.WriteString(fmt.Sprintf("- Medium: %d\n", mediumCount))
        sb.WriteString(fmt.Sprintf("- Low: %d\n", lowCount))
        sb.WriteString(fmt.Sprintf("- Total findings: %d\n\n", len(findings)))
        
        // Add categorized summaries
        keyTypes, credTypes, impls := r.categorizeFindingsByType(findings)
        
        if len(keyTypes) > 0 {
            sb.WriteString("Cryptographic Keys Found:\n")
            for keyType, count := range keyTypes {
                sb.WriteString(fmt.Sprintf("- %s: %d\n", keyType, count))
            }
            sb.WriteString("\n")
        }
        
        if len(credTypes) > 0 {
            sb.WriteString("Credentials Found:\n")
            for credType, count := range credTypes {
                sb.WriteString(fmt.Sprintf("- %s: %d\n", credType, count))
            }
            sb.WriteString("\n")
        }
        
        if len(impls) > 0 {
            sb.WriteString("Crypto Implementations Found:\n")
            for implType, count := range impls {
                sb.WriteString(fmt.Sprintf("- %s: %d\n", implType, count))
            }
            sb.WriteString("\n")
        }
        
        // Write detailed findings
        sb.WriteString("Detailed Findings:\n")
        
        for i, finding := range findings {
                sb.WriteString(fmt.Sprintf("\n[%d] %s - %s\n", i+1, finding.Severity, finding.Type))
                sb.WriteString(fmt.Sprintf("    File: %s", finding.File))
                if finding.LineNumber > 0 {
                        sb.WriteString(fmt.Sprintf(" (line %d)", finding.LineNumber))
                }
                sb.WriteString("\n")
                sb.WriteString(fmt.Sprintf("    Description: %s\n", finding.Description))
                
                // Truncate content if too long
                content := finding.Content
                if len(content) > 100 {
                        content = content[:97] + "..."
                }
                sb.WriteString(fmt.Sprintf("    Content: %s\n", content))
                
                // Add vulnerabilities if any
                if len(finding.Vulnerabilities) > 0 {
                        sb.WriteString("    Vulnerabilities:\n")
                        for _, vuln := range finding.Vulnerabilities {
                                sb.WriteString(fmt.Sprintf("    - [%s] %s: %s\n", vuln.Severity, vuln.Type, vuln.Description))
                                sb.WriteString(fmt.Sprintf("      Reference: %s\n", vuln.Reference))
                        }
                        
                        // Add recommendation based on vulnerability type
                        recommendation := getRecommendationForFinding(finding)
                        if recommendation != "" {
                                sb.WriteString("    Recommendation: ")
                                sb.WriteString(recommendation + "\n")
                        }
                }
        }
        
        return sb.String(), nil
}

// generateJSON creates a JSON report
func (r *Reporter) generateJSON(findings []types.Finding) (string, error) {
        // Create a report structure
        report := struct {
                Summary struct {
                        Critical int `json:"critical"`
                        High     int `json:"high"`
                        Medium   int `json:"medium"`
                        Low      int `json:"low"`
                        Total    int `json:"total"`
                } `json:"summary"`
                Findings []types.Finding `json:"findings"`
        }{
                Findings: findings,
        }
        
        // Count vulnerabilities by severity
        for _, finding := range findings {
                switch finding.Severity {
                case "CRITICAL":
                        report.Summary.Critical++
                case "HIGH":
                        report.Summary.High++
                case "MEDIUM":
                        report.Summary.Medium++
                case "LOW":
                        report.Summary.Low++
                }
        }
        report.Summary.Total = len(findings)
        
        // Marshal to JSON
        jsonData, err := json.MarshalIndent(report, "", "  ")
        if err != nil {
                return "", fmt.Errorf("failed to generate JSON report: %w", err)
        }
        
        return string(jsonData), nil
}

// severityRank returns a numeric rank for severity (higher is more severe)
func severityRank(severity string) int {
        switch severity {
        case "CRITICAL":
                return 4
        case "HIGH":
                return 3
        case "MEDIUM":
                return 2
        case "LOW":
                return 1
        default:
                return 0
        }
}

// getRecommendationForFinding provides a recommendation based on the type of finding and vulnerabilities
func getRecommendationForFinding(finding types.Finding) string {
        // Look for specific vulnerabilities
        for _, vuln := range finding.Vulnerabilities {
                switch vuln.Type {
                case "Key Exposure":
                        return "Remove private keys from the repository and store them securely using a key management system. Consider rotating any exposed keys immediately."
                        
                case "Hardcoded Credential":
                        return "Replace hardcoded credentials with environment variables or a secure secrets management system. Rotate any exposed credentials immediately."
                        
                case "Weak Algorithm":
                        return "Replace weak cryptographic algorithms with modern, secure alternatives like AES-256, SHA-256, or higher."
                        
                case "Weak Curve":
                        return "Use stronger elliptic curves such as P-256, P-384, or Curve25519."
                        
                case "Insecure Mode":
                        return "Replace insecure cryptographic modes with authenticated encryption such as GCM or ChaCha20-Poly1305."
                        
                case "Static IV":
                        return "Use a cryptographically secure random number generator to create a unique IV for each encryption operation."
                        
                case "Insecure Randomness":
                        return "Use a cryptographically secure random number generator (CSPRNG) instead of standard random number generators."
                        
                case "Missing Authentication":
                        return "Implement authenticated encryption by adding a MAC or using an AEAD mode like GCM."
                        
                case "Problematic Implementation":
                        return "Update to the latest version of the cryptographic library and follow their secure implementation guidelines."
                }
        }
        
        // If no specific vulnerabilities but the finding is generally vulnerable
        if finding.Vulnerable {
                return "Review and update this cryptographic asset according to current security best practices."
        }
        
        return ""
}

// categorizeFindingsByType categorizes findings by type into crypto keys, credentials, and implementations
func (r *Reporter) categorizeFindingsByType(findings []types.Finding) (map[string]int, map[string]int, map[string]int) {
        keyTypes := make(map[string]int)
        credTypes := make(map[string]int)
        implTypes := make(map[string]int)
        
        // Define categories
        keyPrefixes := []string{"Private Key", "Public Key", "RSA", "EC", "DSA", "PGP", "SSH", "Certificate"}
        credPrefixes := []string{"Access Key", "Secret Key", "API Key", "Token", "OAuth", "Password", "Credential"}
        implPrefixes := []string{"Crypto Implementation", "Crypto File", "Crypto File Extension"}
        
        for _, finding := range findings {
                // Check if this is a key type
                for _, prefix := range keyPrefixes {
                        if strings.Contains(finding.Type, prefix) {
                                keyTypes[finding.Type]++
                                break
                        }
                }
                
                // Check if this is a credential type
                for _, prefix := range credPrefixes {
                        if strings.Contains(finding.Type, prefix) {
                                credTypes[finding.Type]++
                                break
                        }
                }
                
                // Check if this is an implementation type
                for _, prefix := range implPrefixes {
                        if strings.Contains(finding.Type, prefix) {
                                implTypes[finding.Type]++
                                break
                        }
                }
        }
        
        return keyTypes, credTypes, implTypes
}
