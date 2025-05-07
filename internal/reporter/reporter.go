package reporter

import (
        "encoding/json"
        "fmt"
        "sort"
        "strings"
        "time"

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

// ANSI color codes
const (
        ResetColor    = "\033[0m"
        BoldText      = "\033[1m"
        RedText       = "\033[31m"
        GreenText     = "\033[32m"
        YellowText    = "\033[33m"
        BlueText      = "\033[34m"
        MagentaText   = "\033[35m"
        CyanText      = "\033[36m"
        WhiteText     = "\033[37m"
        RedBg         = "\033[41m"
        GreenBg       = "\033[42m"
        YellowBg      = "\033[43m"
        BlueBg        = "\033[44m"
        MagentaBg     = "\033[45m"
        CyanBg        = "\033[46m"
        WhiteBg       = "\033[47m"
)

// generateText creates a text report with enhanced formatting and colors
func (r *Reporter) generateText(findings []types.Finding) (string, error) {
        var sb strings.Builder
        
        // Create a fancy header
        sb.WriteString("\n")
        sb.WriteString(fmt.Sprintf("%s%s╔═══════════════════════════════════════════════════════════╗%s\n", BoldText, BlueBg, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s║                CRYPTOSCAN SECURITY REPORT                 ║%s\n", BoldText, BlueBg, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s╚═══════════════════════════════════════════════════════════╝%s\n", BoldText, BlueBg, ResetColor))
        sb.WriteString("\n")
        
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
        
        // Write summary section with a nice box
        sb.WriteString(fmt.Sprintf("%s%s╔═════════════════════════════╗%s\n", BoldText, CyanText, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s║         RISK SUMMARY        ║%s\n", BoldText, CyanText, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s╚═════════════════════════════╝%s\n", BoldText, CyanText, ResetColor))
        
        // Show severity counts with appropriate colors
        sb.WriteString(fmt.Sprintf("%s%s%s CRITICAL: %s%d%s findings\n", BoldText, RedBg, WhiteText, ResetColor, criticalCount, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s HIGH:     %s%d%s findings\n", BoldText, RedText, ResetColor, highCount, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s MEDIUM:   %s%d%s findings\n", BoldText, YellowText, ResetColor, mediumCount, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s LOW:      %s%d%s findings\n", BoldText, GreenText, ResetColor, lowCount, ResetColor))
        
        // Total with percentage of vulnerable assets
        totalVulnerable := 0
        for _, finding := range findings {
                if finding.Vulnerable {
                        totalVulnerable++
                }
        }
        
        if len(findings) > 0 {
                percentage := float64(totalVulnerable) / float64(len(findings)) * 100
                sb.WriteString(fmt.Sprintf("\nVulnerable: %s%d%s of %d (%.1f%%)\n", BoldText, totalVulnerable, ResetColor, len(findings), percentage))
        }
        sb.WriteString("\n")
        
        // Add categorized summaries with colored headers
        keyTypes, credTypes, impls := r.categorizeFindingsByType(findings)
        
        sb.WriteString(fmt.Sprintf("%s%s╔═════════════════════════════╗%s\n", BoldText, CyanText, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s║      ASSET DISTRIBUTION     ║%s\n", BoldText, CyanText, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s╚═════════════════════════════╝%s\n", BoldText, CyanText, ResetColor))
        
        if len(keyTypes) > 0 {
                sb.WriteString(fmt.Sprintf("%s%sCryptographic Keys:%s\n", BoldText, MagentaText, ResetColor))
                for keyType, count := range keyTypes {
                        sb.WriteString(fmt.Sprintf("  %s%s%s: %d\n", BoldText, keyType, ResetColor, count))
                }
                sb.WriteString("\n")
        }
        
        if len(credTypes) > 0 {
                sb.WriteString(fmt.Sprintf("%s%sCredentials:%s\n", BoldText, BlueText, ResetColor))
                for credType, count := range credTypes {
                        sb.WriteString(fmt.Sprintf("  %s%s%s: %d\n", BoldText, credType, ResetColor, count))
                }
                sb.WriteString("\n")
        }
        
        if len(impls) > 0 {
                sb.WriteString(fmt.Sprintf("%s%sCrypto Implementations:%s\n", BoldText, GreenText, ResetColor))
                for implType, count := range impls {
                        sb.WriteString(fmt.Sprintf("  %s%s%s: %d\n", BoldText, implType, ResetColor, count))
                }
                sb.WriteString("\n")
        }
        
        // Top Findings section
        sb.WriteString(fmt.Sprintf("%s%s╔═════════════════════════════╗%s\n", BoldText, CyanText, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s║        TOP FINDINGS         ║%s\n", BoldText, CyanText, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s╚═════════════════════════════╝%s\n", BoldText, CyanText, ResetColor))
        
        // Calculate how many findings to show (max 10 or all if less than 10)
        topCount := 10
        if len(findings) < topCount {
                topCount = len(findings)
        }
        
        // Write detailed findings with improved formatting
        for i := 0; i < topCount; i++ {
                finding := findings[i]
                
                // Choose color based on severity
                severityColor := GreenText
                switch finding.Severity {
                case "CRITICAL":
                        severityColor = RedBg
                case "HIGH":
                        severityColor = RedText
                case "MEDIUM":
                        severityColor = YellowText
                }
                
                // Finding header with severity-appropriate color
                sb.WriteString(fmt.Sprintf("%s%s[%s]%s %s\n", BoldText, severityColor, finding.Severity, ResetColor, finding.Type))
                
                // File info with line number if available
                sb.WriteString(fmt.Sprintf("  %sFile:%s %s", BoldText, ResetColor, finding.File))
                if finding.LineNumber > 0 {
                        sb.WriteString(fmt.Sprintf(" (line %d)", finding.LineNumber))
                }
                sb.WriteString("\n")
                
                // Description
                if finding.Description != "" {
                        sb.WriteString(fmt.Sprintf("  %sDescription:%s %s\n", BoldText, ResetColor, finding.Description))
                }
                
                // Truncate content if too long
                content := finding.Content
                if len(content) > 80 {
                        content = content[:77] + "..."
                }
                sb.WriteString(fmt.Sprintf("  %sContent:%s %s\n", BoldText, ResetColor, content))
                
                // Add vulnerabilities with proper formatting
                if len(finding.Vulnerabilities) > 0 {
                        sb.WriteString(fmt.Sprintf("  %sVulnerabilities:%s\n", BoldText, ResetColor))
                        for _, vuln := range finding.Vulnerabilities {
                                // Choose color based on vulnerability severity
                                vulnColor := GreenText
                                switch vuln.Severity {
                                case "CRITICAL":
                                        vulnColor = RedBg
                                case "HIGH":
                                        vulnColor = RedText
                                case "MEDIUM":
                                        vulnColor = YellowText
                                }
                                
                                sb.WriteString(fmt.Sprintf("  %s%s- [%s]%s %s: %s\n", 
                                        BoldText, vulnColor, vuln.Severity, ResetColor, vuln.Type, vuln.Description))
                                
                                // Make reference links stand out
                                if vuln.Reference != "" {
                                        sb.WriteString(fmt.Sprintf("    %sReference:%s %s%s%s\n", 
                                                BoldText, ResetColor, CyanText, vuln.Reference, ResetColor))
                                }
                        }
                        
                        // Add recommendation based on vulnerability type with emphasis
                        recommendation := getRecommendationForFinding(finding)
                        if recommendation != "" {
                                sb.WriteString(fmt.Sprintf("  %s%sRecommendation:%s %s\n", 
                                        BoldText, YellowText, ResetColor, recommendation))
                        }
                }
                
                // Add a separator between findings
                sb.WriteString("\n")
        }
        
        // If there are more findings than we showed in the top section
        if len(findings) > topCount {
                sb.WriteString(fmt.Sprintf("%s... and %d more findings (use --verbose for full report)%s\n\n", 
                        YellowText, len(findings)-topCount, ResetColor))
        }
        
        // Add a helpful footer
        sb.WriteString(fmt.Sprintf("%s%s╔═══════════════════════════════════════════════════════════╗%s\n", BoldText, BlueBg, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s║ For detailed remediation guidance, use the dashboard view  ║%s\n", BoldText, BlueBg, ResetColor))
        sb.WriteString(fmt.Sprintf("%s%s╚═══════════════════════════════════════════════════════════╝%s\n", BoldText, BlueBg, ResetColor))
        
        return sb.String(), nil
}

// generateJSON creates an enhanced JSON report with additional metadata
func (r *Reporter) generateJSON(findings []types.Finding) (string, error) {
        // Count vulnerable items
        totalVulnerable := 0
        for _, finding := range findings {
                if finding.Vulnerable {
                        totalVulnerable++
                }
        }
        
        // Calculate vulnerability percentage
        vulnPercentage := 0.0
        if len(findings) > 0 {
                vulnPercentage = float64(totalVulnerable) / float64(len(findings)) * 100
        }
        
        // Get categorized stats
        keyTypes, credTypes, implTypes := r.categorizeFindingsByType(findings)
        
        // Convert maps to sorted arrays for consistent JSON output
        type CategoryCount struct {
                Type  string `json:"type"`
                Count int    `json:"count"`
        }
        
        // Function to convert map to sorted array
        mapToSortedArray := func(m map[string]int) []CategoryCount {
                var result []CategoryCount
                for k, v := range m {
                        result = append(result, CategoryCount{Type: k, Count: v})
                }
                // Sort by count (descending) then by name
                sort.Slice(result, func(i, j int) bool {
                        if result[i].Count != result[j].Count {
                                return result[i].Count > result[j].Count
                        }
                        return result[i].Type < result[j].Type
                })
                return result
        }
        
        // Create a comprehensive report structure
        report := struct {
                Metadata struct {
                        GeneratedAt      string  `json:"generated_at"`
                        ScanDuration     string  `json:"scan_duration,omitempty"`
                        Version          string  `json:"version"`
                        CommandLine      string  `json:"command_line,omitempty"`
                } `json:"metadata"`
                
                Summary struct {
                        Critical         int     `json:"critical"`
                        High             int     `json:"high"`
                        Medium           int     `json:"medium"`
                        Low              int     `json:"low"`
                        Total            int     `json:"total"`
                        VulnerableCount  int     `json:"vulnerable_count"`
                        VulnerablePercent float64 `json:"vulnerable_percent"`
                } `json:"summary"`
                
                Distribution struct {
                        Keys            []CategoryCount `json:"cryptographic_keys"`
                        Credentials     []CategoryCount `json:"credentials"`
                        Implementations []CategoryCount `json:"implementations"`
                } `json:"distribution"`
                
                Findings []types.Finding `json:"findings"`
        }{
                Findings: findings,
        }
        
        // Set metadata
        report.Metadata.GeneratedAt = time.Now().Format(time.RFC3339)
        report.Metadata.Version = "1.0.0" // Set your app version here
        
        // Set summary data
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
        report.Summary.VulnerableCount = totalVulnerable
        report.Summary.VulnerablePercent = vulnPercentage
        
        // Set distribution data
        report.Distribution.Keys = mapToSortedArray(keyTypes)
        report.Distribution.Credentials = mapToSortedArray(credTypes)
        report.Distribution.Implementations = mapToSortedArray(implTypes)
        
        // Marshal to JSON with pretty formatting
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
