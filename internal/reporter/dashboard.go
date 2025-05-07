package reporter

import (
        "fmt"
        "sort"
        "strings"
        "time"

        "github.com/yourusername/cryptoscan/pkg/types"
)

// ANSI color codes
const (
        Reset      = "\033[0m"
        Bold       = "\033[1m"
        Underline  = "\033[4m"
        Red        = "\033[31m"
        Green      = "\033[32m"
        Yellow     = "\033[33m"
        Blue       = "\033[34m"
        Magenta    = "\033[35m"
        Cyan       = "\033[36m"
        White      = "\033[37m"
        BgRed      = "\033[41m"
        BgGreen    = "\033[42m"
        BgYellow   = "\033[43m"
        BgBlue     = "\033[44m"
        BgMagenta  = "\033[45m"
        BgCyan     = "\033[46m"
        BgWhite    = "\033[47m"
)

// Dashboard represents an interactive dashboard
type Dashboard struct {
        findings     []types.Finding
        targetPath   string
        provider     string
        scanTime     time.Time
}

// NewDashboard creates a new dashboard
func NewDashboard(findings []types.Finding, targetPath string, provider string) *Dashboard {
        return &Dashboard{
                findings:   findings,
                targetPath: targetPath,
                provider:   provider,
                scanTime:   time.Now(),
        }
}

// Display shows the interactive dashboard
func (d *Dashboard) Display() {
        // Clear screen
        fmt.Print("\033[H\033[2J")

        d.printHeader()
        d.printSummary()
        d.printSeverityDistribution()
        d.printTypeDistribution()
        d.printTopFindings(10)
        d.printFooter()
}

// printHeader prints an enhanced dashboard header with logo and scan information
func (d *Dashboard) printHeader() {
        // Create an ASCII logo for visual appeal
        logo := []string{
                "   ____                  _        ____                   ",
                "  / ___|_ __ _   _ _ __ | |_ ___ / ___|  ___ __ _ _ __  ",
                " | |   | '__| | | | '_ \\| __/ _ \\\\___ \\ / __/ _` | '_ \\ ",
                " | |___| |  | |_| | |_) | || (_) |___) | (_| (_| | | | |",
                "  \\____|_|   \\__, | .__/ \\__\\___/|____/ \\___\\__,_|_| |_|",
                "             |___/|_|                                    ",
        }
        
        // Print logo with gradient colors
        colors := []string{Cyan, Blue, Magenta}
        fmt.Println()
        for i, line := range logo {
                colorIndex := i % len(colors)
                fmt.Printf("%s%s%s%s\n", Bold, colors[colorIndex], line, Reset)
        }
        
        // Main dashboard header box
        fmt.Println()
        fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", Bold, BgBlue, Reset)
        fmt.Printf("%s%s║                    CRYPTOSCAN VULNERABILITY DASHBOARD                        ║%s\n", Bold, BgBlue, Reset)
        fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", Bold, BgBlue, Reset)
        fmt.Println()
        
        // Scan information in a visually appealing format
        fmt.Printf("%s%s╭─ SCAN INFORMATION %s%s\n", Bold, Blue, strings.Repeat("─", 61), Reset)
        
        // Target info with appropriate formatting
        fmt.Printf("%s%s│%s %sTarget:%s %s%s%s\n", 
                Bold, Blue, Reset, 
                Bold, Reset, 
                Underline, d.targetPath, Reset)
        
        // Provider info if available
        if d.provider != "" && d.provider != "Unknown" {
                // Format provider name properly
                providerName := strings.ToUpper(d.provider[:1]) + d.provider[1:]
                
                // Select color based on provider
                providerColor := Blue
                switch strings.ToLower(d.provider) {
                case "github":
                        providerColor = Magenta
                case "gitlab":
                        providerColor = Yellow
                case "bitbucket":
                        providerColor = Blue
                }
                
                fmt.Printf("%s%s│%s %sProvider:%s %s%s%s%s\n", 
                        Bold, Blue, Reset, 
                        Bold, Reset, 
                        Bold, providerColor, providerName, Reset)
        } else if d.provider == "Unknown" {
                fmt.Printf("%s%s│%s %sProvider:%s Local Directory\n", 
                        Bold, Blue, Reset, 
                        Bold, Reset)
        }
        
        // Scan time with fancy formatting
        fmt.Printf("%s%s│%s %sScan Time:%s %s\n", 
                Bold, Blue, Reset, 
                Bold, Reset, 
                d.scanTime.Format("2006-01-02 15:04:05"))
        
        // Assets count with color based on number
        assetColor := Green
        if len(d.findings) > 50 {
                assetColor = Yellow
        }
        if len(d.findings) > 100 {
                assetColor = Red
        }
        
        fmt.Printf("%s%s│%s %sAssets Found:%s %s%d%s cryptographic assets\n", 
                Bold, Blue, Reset, 
                Bold, Reset, 
                Bold+assetColor, len(d.findings), Reset)
        
        // Version information
        fmt.Printf("%s%s│%s %sVersion:%s 1.0.0\n", 
                Bold, Blue, Reset, 
                Bold, Reset)
        
        // Bottom border for the scan info section
        fmt.Printf("%s%s╰%s%s\n", Bold, Blue, strings.Repeat("─", 77), Reset)
        fmt.Println()
}

// printSummary prints an enhanced risk summary with visual indicators
func (d *Dashboard) printSummary() {
        criticalCount := 0
        highCount := 0
        mediumCount := 0
        lowCount := 0
        vulnCount := 0

        for _, finding := range d.findings {
                if finding.Vulnerable {
                        vulnCount++
                }
                
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
        
        // Add section title with gradient
        fmt.Println()
        fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", Bold, Cyan, Reset)
        fmt.Printf("%s%s║                              RISK SUMMARY                                    ║%s\n", Bold, Cyan, Reset)
        fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", Bold, Cyan, Reset)
        
        // Calculate risk score (weighted average based on severity)
        totalFindings := len(d.findings)
        riskScore := 0.0
        if totalFindings > 0 {
                riskScore = (float64(criticalCount)*10 + float64(highCount)*7 + float64(mediumCount)*4 + float64(lowCount)*1) / float64(totalFindings)
        }
        
        // Determine risk level and appropriate colors
        riskLevel := ""
        riskColor := ""
        riskIcon := ""
        if riskScore >= 8 {
                riskLevel = "CRITICAL"
                riskColor = BgRed + White
                riskIcon = "‼️ "
        } else if riskScore >= 5 {
                riskLevel = "HIGH"
                riskColor = Red
                riskIcon = "⚠️ "
        } else if riskScore >= 3 {
                riskLevel = "MEDIUM"
                riskColor = Yellow
                riskIcon = "⚠️ "
        } else if riskScore > 0 {
                riskLevel = "LOW"
                riskColor = Green
                riskIcon = "ℹ️ "
        } else {
                riskLevel = "NONE"
                riskColor = Green
                riskIcon = "✓ "
        }
        
        // Calculate vulnerability percentage
        vulnPercentage := 0.0
        if totalFindings > 0 {
                vulnPercentage = float64(vulnCount) / float64(totalFindings) * 100
        }
        
        // Print main risk score in visually distinct box
        fmt.Println()
        fmt.Printf("  %sOverall Risk Assessment:%s\n", Bold, Reset)
        fmt.Printf("  ┌────────────────────────────┐\n")
        fmt.Printf("  │ %sRisk Score:%s %.1f/10         │\n", Bold, Reset, riskScore)
        fmt.Printf("  │ %sRisk Level:%s %s%s%s%s        │\n", Bold, Reset, Bold, riskColor, riskLevel, Reset)
        fmt.Printf("  │ %sVulnerable Assets:%s %.1f%%     │\n", Bold, Reset, vulnPercentage)
        fmt.Printf("  └────────────────────────────┘\n")
        fmt.Println()
        
        // Print severity counts with improved styling
        fmt.Printf("  %sSeverity Breakdown:%s\n", Bold, Reset)
        fmt.Printf("  ┌───────────┬───────────┬────────────┬──────────┐\n")
        fmt.Printf("  │ %s%sCRITICAL%s  │  %s%sHIGH%s    │  %s%sMEDIUM%s   │  %s%sLOW%s     │\n", 
                Bold, BgRed+White, Reset, Bold, Red, Reset, Bold, Yellow, Reset, Bold, Green, Reset)
        fmt.Printf("  ├───────────┼───────────┼────────────┼──────────┤\n")
        fmt.Printf("  │    %s%d%s     │    %s%d%s     │     %s%d%s     │    %s%d%s     │\n", 
                Bold, criticalCount, Reset, Bold, highCount, Reset, Bold, mediumCount, Reset, Bold, lowCount, Reset)
        fmt.Printf("  └───────────┴───────────┴────────────┴──────────┘\n")
        fmt.Println()
        
        // Add risk interpretation based on scores
        fmt.Printf("  %sRisk Interpretation:%s\n", Bold, Reset)
        if riskScore >= 8 {
                fmt.Printf("  %s%s%s Your system has CRITICAL security issues that require immediate attention.%s\n", 
                        Bold, Red, riskIcon, Reset)
        } else if riskScore >= 5 {
                fmt.Printf("  %s%s%s Your system has HIGH risk security issues that should be addressed soon.%s\n", 
                        Bold, Red, riskIcon, Reset)
        } else if riskScore >= 3 {
                fmt.Printf("  %s%s%s Your system has MEDIUM security concerns that should be reviewed.%s\n", 
                        Bold, Yellow, riskIcon, Reset)
        } else if riskScore > 0 {
                fmt.Printf("  %s%s%s Your system has minor security issues with low severity.%s\n", 
                        Bold, Green, riskIcon, Reset)
        } else {
                fmt.Printf("  %s%s%s No significant security issues detected. Great job!%s\n", 
                        Bold, Green, riskIcon, Reset)
        }
        
        // Vulnerability count summary
        if totalFindings > 0 {
                fmt.Printf("\n  %s%d%s of %d findings (%.1f%%) contain vulnerabilities that should be addressed.\n", 
                        Bold, vulnCount, Reset, totalFindings, vulnPercentage)
        }
        
        fmt.Println()
}

// printSeverityDistribution prints a visual distribution of severities
func (d *Dashboard) printSeverityDistribution() {
        criticalCount := 0
        highCount := 0
        mediumCount := 0
        lowCount := 0
        
        for _, finding := range d.findings {
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
        
        total := len(d.findings)
        if total == 0 {
                return
        }
        
        fmt.Printf("%s%s╔══════════════════════════════════╗%s\n", Bold, Cyan, Reset)
        fmt.Printf("%s%s║       SEVERITY DISTRIBUTION      ║%s\n", Bold, Cyan, Reset)
        fmt.Printf("%s%s╚══════════════════════════════════╝%s\n", Bold, Cyan, Reset)
        
        // Horizontal bar chart
        width := 50
        criticalWidth := width * criticalCount / total
        highWidth := width * highCount / total
        mediumWidth := width * mediumCount / total
        lowWidth := width * lowCount / total
        
        // Make sure we have at least 1 character if count > 0
        if criticalCount > 0 && criticalWidth == 0 {
                criticalWidth = 1
        }
        if highCount > 0 && highWidth == 0 {
                highWidth = 1
        }
        if mediumCount > 0 && mediumWidth == 0 {
                mediumWidth = 1
        }
        if lowCount > 0 && lowWidth == 0 {
                lowWidth = 1
        }
        
        // Adjust widths to fit
        remainingWidth := width - criticalWidth - highWidth - mediumWidth - lowWidth
        if remainingWidth < 0 {
                // Scale down proportionally if we exceed width
                totalUsed := criticalWidth + highWidth + mediumWidth + lowWidth
                scaleFactor := float64(width) / float64(totalUsed)
                
                criticalWidth = int(float64(criticalWidth) * scaleFactor)
                highWidth = int(float64(highWidth) * scaleFactor)
                mediumWidth = int(float64(mediumWidth) * scaleFactor)
                lowWidth = int(float64(lowWidth) * scaleFactor)
                
                // Ensure that the total width is exactly the desired width
                totalNew := criticalWidth + highWidth + mediumWidth + lowWidth
                if totalNew < width {
                        // Add the remaining to the largest category
                        max := max4(criticalWidth, highWidth, mediumWidth, lowWidth)
                        if max == criticalWidth {
                                criticalWidth += width - totalNew
                        } else if max == highWidth {
                                highWidth += width - totalNew
                        } else if max == mediumWidth {
                                mediumWidth += width - totalNew
                        } else {
                                lowWidth += width - totalNew
                        }
                }
        }
        
        // Draw the bar chart with a clearer visual hierarchy
        fmt.Print("  ")
        
        // Use different characters for each severity level for better differentiation
        fmt.Print(strings.Repeat(BgRed+"▓", criticalWidth))    // Dense dotted for critical
        fmt.Print(strings.Repeat(Red+"▒", highWidth))          // Medium dotted for high
        fmt.Print(strings.Repeat(Yellow+"░", mediumWidth))     // Light dotted for medium
        fmt.Print(strings.Repeat(Green+"·", lowWidth))         // Dots for low
        
        // Fill remaining space
        fmt.Print(strings.Repeat(" ", width-criticalWidth-highWidth-mediumWidth-lowWidth))
        fmt.Println(Reset)
        
        // Chart legend with severity and percentages
        criticalPercent := float64(criticalCount) / float64(total) * 100
        highPercent := float64(highCount) / float64(total) * 100
        mediumPercent := float64(mediumCount) / float64(total) * 100
        lowPercent := float64(lowCount) / float64(total) * 100
        
        fmt.Printf("  %s%s▓ CRITICAL%s: %d (%.1f%%)  ", Bold, BgRed, Reset, criticalCount, criticalPercent)
        fmt.Printf("%s%s▒ HIGH%s: %d (%.1f%%)\n", Bold, Red, Reset, highCount, highPercent)
        fmt.Printf("  %s%s░ MEDIUM%s: %d (%.1f%%)    ", Bold, Yellow, Reset, mediumCount, mediumPercent)
        fmt.Printf("%s%s· LOW%s: %d (%.1f%%)\n", Bold, Green, Reset, lowCount, lowPercent)
        fmt.Println()
}

// max4 returns the maximum of four integers
func max4(a, b, c, d int) int {
        max := a
        if b > max {
                max = b
        }
        if c > max {
                max = c
        }
        if d > max {
                max = d
        }
        return max
}

// printTypeDistribution prints the distribution of finding types with visual bars
func (d *Dashboard) printTypeDistribution() {
        // Get type counts
        keyTypes, credTypes, implTypes := d.categorizeFindingsByType()
        
        fmt.Printf("%s%s╔══════════════════════════════════╗%s\n", Bold, Cyan, Reset)
        fmt.Printf("%s%s║        TYPE DISTRIBUTION         ║%s\n", Bold, Cyan, Reset)
        fmt.Printf("%s%s╚══════════════════════════════════╝%s\n", Bold, Cyan, Reset)
        
        // Convert maps to sorted slices for consistent display order
        type TypeCount struct {
                Type  string
                Count int
        }
        
        // Function to convert map to sorted slice (by count, descending)
        mapToSortedSlice := func(m map[string]int) []TypeCount {
                slice := make([]TypeCount, 0, len(m))
                for t, c := range m {
                        slice = append(slice, TypeCount{Type: t, Count: c})
                }
                sort.Slice(slice, func(i, j int) bool {
                        return slice[i].Count > slice[j].Count
                })
                return slice
        }
        
        // Get sorted slices for each category
        sortedKeyTypes := mapToSortedSlice(keyTypes)
        sortedCredTypes := mapToSortedSlice(credTypes)
        sortedImplTypes := mapToSortedSlice(implTypes)
        
        // Find the maximum count across all types for proper bar scaling
        maxCount := 0
        for _, tc := range sortedKeyTypes {
                if tc.Count > maxCount {
                        maxCount = tc.Count
                }
        }
        for _, tc := range sortedCredTypes {
                if tc.Count > maxCount {
                        maxCount = tc.Count
                }
        }
        for _, tc := range sortedImplTypes {
                if tc.Count > maxCount {
                        maxCount = tc.Count
                }
        }
        
        // Define visual bar max width
        maxBarWidth := 30
        
        // Function to print a category with visual bars
        printTypeCategory := func(title string, color string, types []TypeCount) {
                if len(types) == 0 {
                        return
                }
                
                fmt.Printf("%s%s%s:%s\n", Bold, color, title, Reset)
                
                for _, tc := range types {
                        // Calculate bar width proportional to the count
                        barWidth := 1
                        if maxCount > 0 {
                                barWidth = tc.Count * maxBarWidth / maxCount
                                if barWidth < 1 {
                                        barWidth = 1
                                }
                        }
                        
                        // Print the type with a visual bar
                        typeLabel := tc.Type
                        if len(typeLabel) > 20 {
                                typeLabel = typeLabel[:17] + "..."
                        }
                        
                        // Right-align the count within a fixed width
                        countStr := fmt.Sprintf("%d", tc.Count)
                        padding := 5 - len(countStr)
                        countDisplay := strings.Repeat(" ", padding) + countStr
                        
                        // Print the line with proper alignment
                        fmt.Printf("  %s%-20s%s │%s ", Bold, typeLabel, Reset, countDisplay)
                        fmt.Print(color)
                        fmt.Print(strings.Repeat("▮", barWidth))  // Using a different character for type bars
                        fmt.Println(Reset)
                }
                fmt.Println()
        }
        
        // Print all categories
        printTypeCategory("Cryptographic Keys", Magenta, sortedKeyTypes)
        printTypeCategory("Credentials", Blue, sortedCredTypes)
        printTypeCategory("Implementations", Green, sortedImplTypes)
}

// printTopFindings prints the top findings by severity with enhanced formatting
func (d *Dashboard) printTopFindings(count int) {
        // Sort findings by severity (using the existing sort functionality)
        sortedFindings := make([]types.Finding, len(d.findings))
        copy(sortedFindings, d.findings)
        
        // Sort by severity and vulnerability count
        sort.Slice(sortedFindings, func(i, j int) bool {
                iRank := severityRank(sortedFindings[i].Severity)
                jRank := severityRank(sortedFindings[j].Severity)
                
                if iRank != jRank {
                        return iRank > jRank
                }
                
                // If same severity, sort by vulnerability count (more vulnerabilities first)
                return len(sortedFindings[i].Vulnerabilities) > len(sortedFindings[j].Vulnerabilities)
        })
        
        // Determine how many to show
        showCount := count
        if showCount > len(sortedFindings) {
                showCount = len(sortedFindings)
        }
        
        fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", Bold, Cyan, Reset)
        fmt.Printf("%s%s║         TOP %2d FINDINGS                                                      ║%s\n", Bold, Cyan, showCount, Reset)
        fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", Bold, Cyan, Reset)
        
        for i := 0; i < showCount; i++ {
                finding := sortedFindings[i]
                
                // Determine color based on severity
                severityColor := Green
                severityBg := ""
                switch finding.Severity {
                case "CRITICAL":
                        severityColor = Red
                        severityBg = BgRed
                case "HIGH":
                        severityColor = Red
                case "MEDIUM":
                        severityColor = Yellow
                }
                
                // Draw a visually distinct box for each finding
                fmt.Printf("%s%s[%s%s %s %s]%s %s%s%s\n", 
                        Bold, severityColor,
                        severityBg, White, finding.Severity, Reset+severityColor,
                        Reset,
                        Bold, finding.Type, Reset)
                
                // File info with line number if available
                fmt.Printf("  %sFile:%s %s%s%s", Bold, Reset, Underline, finding.File, Reset)
                if finding.LineNumber > 0 {
                        fmt.Printf(" (line %s%d%s)", Bold, finding.LineNumber, Reset)
                }
                fmt.Println()
                
                // Truncate content if too long
                content := finding.Content
                if len(content) > 70 {
                        content = content[:67] + "..."
                }
                // Replace tabs and newlines for better display
                content = strings.ReplaceAll(content, "\t", "  ")
                content = strings.ReplaceAll(content, "\n", "↵ ")
                fmt.Printf("  %sContent:%s %s\n", Bold, Reset, content)
                
                // Show vulnerabilities with color-coded severity and improved formatting
                if len(finding.Vulnerabilities) > 0 {
                        fmt.Printf("  %sVulnerabilities:%s\n", Bold, Reset)
                        for _, vuln := range finding.Vulnerabilities {
                                // Choose color based on vulnerability severity
                                vulnColor := Green
                                vulnBg := ""
                                switch vuln.Severity {
                                case "CRITICAL":
                                        vulnColor = Red
                                        vulnBg = BgRed
                                case "HIGH":
                                        vulnColor = Red
                                case "MEDIUM":
                                        vulnColor = Yellow
                                }
                                
                                fmt.Printf("  %s%s- [%s%s %s %s]%s %s: %s\n", 
                                        Bold, vulnColor,
                                        vulnBg, White, vuln.Severity, Reset+vulnColor,
                                        Reset, 
                                        vuln.Type, vuln.Description)
                        }
                        
                        // Add recommendation if any
                        if finding.Vulnerable {
                                // Get recommendation
                                recommendation := getRecommendationForVulnerability(finding)
                                if recommendation != "" {
                                        fmt.Printf("  %s%sRecommendation:%s %s\n", 
                                                Bold, Yellow, Reset, recommendation)
                                }
                        }
                }
                
                // Add a visual separator between findings
                fmt.Printf("%s%s%s\n", Cyan, strings.Repeat("─", 78), Reset)
        }
        
        // Display pagination info if there are more findings
        if len(sortedFindings) > showCount {
                fmt.Printf("\n%s%s... and %d more findings (use -v/--verbose for complete report)%s\n\n", 
                        Bold, Yellow, len(sortedFindings)-showCount, Reset)
        }
}

// getRecommendationForVulnerability provides targeted recommendations based on finding type
func getRecommendationForVulnerability(finding types.Finding) string {
        // First check for specific vulnerabilities
        for _, vuln := range finding.Vulnerabilities {
                switch vuln.Type {
                case "Key Exposure":
                        return "Remove private keys from repository and store them securely using a key management system"
                        
                case "Hardcoded Credential":
                        return "Replace hardcoded credentials with environment variables or a secure secrets management system"
                        
                case "Weak Algorithm":
                        return "Replace with modern algorithms like AES-256, SHA-256, or higher"
                        
                case "Weak Curve":
                        return "Use stronger elliptic curves such as P-256, P-384, or Curve25519"
                        
                case "Insecure Mode":
                        return "Replace with authenticated encryption such as GCM or ChaCha20-Poly1305"
                        
                case "Static IV":
                        return "Generate a unique IV for each encryption operation using a CSPRNG"
                        
                case "Insecure Randomness":
                        return "Use a cryptographically secure random number generator (CSPRNG)"
                }
        }
        
        // Generic recommendations based on finding type
        if strings.Contains(finding.Type, "Private Key") || strings.Contains(finding.Type, "RSA Private") {
                return "Store private keys securely outside of code repositories"
        }
        
        if strings.Contains(finding.Type, "API Key") || strings.Contains(finding.Type, "Token") {
                return "Use environment variables or secrets management for sensitive credentials"
        }
        
        if strings.Contains(finding.Type, "Password") {
                return "Use a secure password manager or vault and never hardcode passwords"
        }
        
        // Generic recommendation if nothing specific applies
        return "Review and update according to current security best practices"
}

// printFooter prints an enhanced dashboard footer with usage tips
func (d *Dashboard) printFooter() {
        // Current time for the dashboard
        currentTime := time.Now().Format("2006-01-02 15:04:05")
        
        // Calculate vulnerability percentages
        totalCritical := 0
        totalHigh := 0
        totalVulnerable := 0
        for _, finding := range d.findings {
                if finding.Vulnerable {
                        totalVulnerable++
                        if finding.Severity == "CRITICAL" {
                                totalCritical++
                        } else if finding.Severity == "HIGH" {
                                totalHigh++
                        }
                }
        }
        
        criticalPercentage := 0.0
        highPercentage := 0.0
        if len(d.findings) > 0 {
                criticalPercentage = float64(totalCritical) / float64(len(d.findings)) * 100
                highPercentage = float64(totalHigh) / float64(len(d.findings)) * 100
        }
        
        // Add a summary section above the footer
        fmt.Println()
        fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", Bold, Yellow, Reset)
        fmt.Printf("%s%s║                               SUMMARY                                        ║%s\n", Bold, Yellow, Reset)
        fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", Bold, Yellow, Reset)
        
        // Show key metrics in a clean format
        fmt.Printf("%s• Scan completed:%s %s\n", Bold, Reset, currentTime)
        fmt.Printf("%s• Critical issues:%s %.1f%% of findings\n", Bold, Reset, criticalPercentage)
        fmt.Printf("%s• High-risk issues:%s %.1f%% of findings\n", Bold, Reset, highPercentage)
        
        // Security summary statement based on findings
        fmt.Println()
        if totalCritical > 0 {
                fmt.Printf("%s%s⚠️  SECURITY ALERT: Critical vulnerabilities detected. Immediate action recommended.%s\n", Bold, Red, Reset)
        } else if totalHigh > 0 {
                fmt.Printf("%s%s⚠️  ATTENTION: High-risk issues detected. Remediation strongly advised.%s\n", Bold, Yellow, Reset)
        } else if totalVulnerable > 0 {
                fmt.Printf("%s%s✓  Low to medium risk issues found. Consider addressing these in future updates.%s\n", Bold, Green, Reset)
        } else {
                fmt.Printf("%s%s✓  No significant security issues detected. Great job!%s\n", Bold, Green, Reset)
        }
        fmt.Println()
        
        // Interactive tips footer
        fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", Bold, BgBlue, Reset)
        fmt.Printf("%s%s║ %sInteractive Commands%s                                                          ║%s\n", Bold, BgBlue, Underline, BgBlue, Reset)
        fmt.Printf("%s%s║ • Press %sCTRL+C%s to exit                                                       ║%s\n", Bold, BgBlue, BgWhite+Blue, BgBlue, Reset)
        fmt.Printf("%s%s║ • Use %s--severity HIGH%s flag for filtering by severity                         ║%s\n", Bold, BgBlue, BgWhite+Blue, BgBlue, Reset)
        fmt.Printf("%s%s║ • Use %s--type \"API Key\"%s flag for filtering by finding type                   ║%s\n", Bold, BgBlue, BgWhite+Blue, BgBlue, Reset)
        fmt.Printf("%s%s║ • Use %s--notify-slack%s flag to send report to configured Slack webhook         ║%s\n", Bold, BgBlue, BgWhite+Blue, BgBlue, Reset)
        fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", Bold, BgBlue, Reset)
}

// categorizeFindingsByType returns maps of key types, credential types, and implementation types
func (d *Dashboard) categorizeFindingsByType() (map[string]int, map[string]int, map[string]int) {
        keyTypes := make(map[string]int)
        credTypes := make(map[string]int)
        implTypes := make(map[string]int)
        
        // Define categories
        keyPrefixes := []string{"Private Key", "Public Key", "RSA", "EC", "DSA", "PGP", "SSH", "Certificate"}
        credPrefixes := []string{"Access Key", "Secret Key", "API Key", "Token", "OAuth", "Password", "Credential"}
        implPrefixes := []string{"Crypto Implementation", "Crypto File", "Crypto File Extension"}
        
        for _, finding := range d.findings {
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