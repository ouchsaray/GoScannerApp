package reporter

import (
	"fmt"
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
	scanTime     time.Time
}

// NewDashboard creates a new dashboard
func NewDashboard(findings []types.Finding, targetPath string) *Dashboard {
	return &Dashboard{
		findings:   findings,
		targetPath: targetPath,
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

// printHeader prints the dashboard header
func (d *Dashboard) printHeader() {
	fmt.Println()
	fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", Bold, BgBlue, Reset)
	fmt.Printf("%s%s║                    CRYPTOSCAN VULNERABILITY DASHBOARD                        ║%s\n", Bold, BgBlue, Reset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", Bold, BgBlue, Reset)
	fmt.Println()
	fmt.Printf("Target: %s%s%s\n", Bold, d.targetPath, Reset)
	fmt.Printf("Scan Time: %s%s%s\n", Bold, d.scanTime.Format("2006-01-02 15:04:05"), Reset)
	fmt.Printf("Found: %s%d%s cryptographic assets\n", Bold, len(d.findings), Reset)
	fmt.Println()
}

// printSummary prints the summary section
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

	fmt.Printf("%s%s╔══════════════════════════════════╗%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s║           RISK SUMMARY           ║%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s╚══════════════════════════════════╝%s\n", Bold, Cyan, Reset)
	
	fmt.Printf("%s%s CRITICAL: %s%d%s findings\n", Bold, BgRed, Reset, criticalCount, Reset)
	fmt.Printf("%s%s HIGH:     %s%d%s findings\n", Bold, Red, Reset, highCount, Reset)
	fmt.Printf("%s%s MEDIUM:   %s%d%s findings\n", Bold, Yellow, Reset, mediumCount, Reset)
	fmt.Printf("%s%s LOW:      %s%d%s findings\n", Bold, Green, Reset, lowCount, Reset)
	fmt.Printf("\nVulnerable: %s%d%s of %d (%.1f%%)\n", Bold, vulnCount, Reset, len(d.findings), 
		float64(vulnCount)/float64(len(d.findings))*100)
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
	
	width := 50
	criticalWidth := width * criticalCount / total
	highWidth := width * highCount / total
	mediumWidth := width * mediumCount / total
	lowWidth := width * lowCount / total
	
	fmt.Printf("%s%s╔══════════════════════════════════╗%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s║       SEVERITY DISTRIBUTION      ║%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s╚══════════════════════════════════╝%s\n", Bold, Cyan, Reset)
	
	fmt.Print("[")
	fmt.Print(strings.Repeat(BgRed+" ", criticalWidth))
	fmt.Print(strings.Repeat(Red+" ", highWidth))
	fmt.Print(strings.Repeat(Yellow+" ", mediumWidth))
	fmt.Print(strings.Repeat(Green+" ", lowWidth))
	fmt.Print(strings.Repeat(" ", width-criticalWidth-highWidth-mediumWidth-lowWidth))
	fmt.Println("]")
	
	fmt.Printf("█ %s%sCRITICAL%s  █ %s%sHIGH%s  █ %s%sMEDIUM%s  █ %s%sLOW%s\n", 
		Bold, BgRed, Reset, Bold, Red, Reset, Bold, Yellow, Reset, Bold, Green, Reset)
	fmt.Println()
}

// printTypeDistribution prints the distribution of finding types
func (d *Dashboard) printTypeDistribution() {
	// Get type counts
	keyTypes, credTypes, implTypes := d.categorizeFindingsByType()
	
	fmt.Printf("%s%s╔══════════════════════════════════╗%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s║        TYPE DISTRIBUTION         ║%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s╚══════════════════════════════════╝%s\n", Bold, Cyan, Reset)
	
	fmt.Printf("%s%sCryptographic Keys:%s\n", Bold, Magenta, Reset)
	for keyType, count := range keyTypes {
		fmt.Printf("  %s%s%s: %d\n", Bold, keyType, Reset, count)
	}
	
	fmt.Printf("\n%s%sCredentials:%s\n", Bold, Blue, Reset)
	for credType, count := range credTypes {
		fmt.Printf("  %s%s%s: %d\n", Bold, credType, Reset, count)
	}
	
	fmt.Printf("\n%s%sImplementations:%s\n", Bold, Green, Reset)
	for implType, count := range implTypes {
		fmt.Printf("  %s%s%s: %d\n", Bold, implType, Reset, count)
	}
	fmt.Println()
}

// printTopFindings prints the top findings by severity
func (d *Dashboard) printTopFindings(count int) {
	// Sort findings by severity (using the existing sort functionality)
	sortedFindings := make([]types.Finding, len(d.findings))
	copy(sortedFindings, d.findings)
	
	// Sort by severity (we'll use a simple bubble sort since we expect small number of items)
	for i := 0; i < len(sortedFindings); i++ {
		for j := i + 1; j < len(sortedFindings); j++ {
			if severityRank(sortedFindings[i].Severity) < severityRank(sortedFindings[j].Severity) {
				sortedFindings[i], sortedFindings[j] = sortedFindings[j], sortedFindings[i]
			}
		}
	}
	
	// Determine how many to show
	showCount := count
	if showCount > len(sortedFindings) {
		showCount = len(sortedFindings)
	}
	
	fmt.Printf("%s%s╔══════════════════════════════════╗%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s║         TOP %2d FINDINGS          ║%s\n", Bold, Cyan, showCount, Reset)
	fmt.Printf("%s%s╚══════════════════════════════════╝%s\n", Bold, Cyan, Reset)
	
	for i := 0; i < showCount; i++ {
		finding := sortedFindings[i]
		
		// Determine color based on severity
		severityColor := Green
		switch finding.Severity {
		case "CRITICAL":
			severityColor = BgRed
		case "HIGH":
			severityColor = Red
		case "MEDIUM":
			severityColor = Yellow
		}
		
		fmt.Printf("%s%s[%s]%s %s\n", Bold, severityColor, finding.Severity, Reset, finding.Type)
		fmt.Printf("  File: %s", finding.File)
		if finding.LineNumber > 0 {
			fmt.Printf(" (line %d)", finding.LineNumber)
		}
		fmt.Println()
		
		// Truncate content if too long
		content := finding.Content
		if len(content) > 60 {
			content = content[:57] + "..."
		}
		fmt.Printf("  Content: %s\n", content)
		
		// Show vulnerabilities
		if len(finding.Vulnerabilities) > 0 {
			for _, vuln := range finding.Vulnerabilities {
				fmt.Printf("  %s%s- [%s] %s%s\n", Bold, Red, vuln.Severity, vuln.Type, Reset)
			}
		}
		fmt.Println()
	}
}

// printFooter prints the dashboard footer
func (d *Dashboard) printFooter() {
	fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", Bold, BgBlue, Reset)
	fmt.Printf("%s%s║ Press CTRL+C to exit                                                         ║%s\n", Bold, BgBlue, Reset)
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