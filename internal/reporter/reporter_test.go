package reporter

import (
        "encoding/json"
        "os"
        "testing"

        "github.com/stretchr/testify/assert"

        "github.com/yourusername/cryptoscan/internal/scanner"
        "github.com/yourusername/cryptoscan/pkg/types"
)

func TestNewReporter(t *testing.T) {
        // Test creating a new reporter with various options
        tests := []struct {
                name     string
                options  []ReporterOption
                expected Reporter
        }{
                {
                        name:    "Default reporter",
                        options: []ReporterOption{},
                        expected: Reporter{
                                verbose:  false,
                                jsonOutput: false,
                                outputFile: "",
                                findings: []types.Finding{},
                        },
                },
                {
                        name:    "Verbose reporter",
                        options: []ReporterOption{WithVerbose(true)},
                        expected: Reporter{
                                verbose:  true,
                                jsonOutput: false,
                                outputFile: "",
                                findings: []types.Finding{},
                        },
                },
                {
                        name:    "JSON output reporter",
                        options: []ReporterOption{WithJSONOutput(true)},
                        expected: Reporter{
                                verbose:  false,
                                jsonOutput: true,
                                outputFile: "",
                                findings: []types.Finding{},
                        },
                },
                {
                        name:    "With output file",
                        options: []ReporterOption{WithOutputFile("output.json")},
                        expected: Reporter{
                                verbose:  false,
                                jsonOutput: false,
                                outputFile: "output.json",
                                findings: []types.Finding{},
                        },
                },
                {
                        name: "With all options",
                        options: []ReporterOption{
                                WithVerbose(true),
                                WithJSONOutput(true),
                                WithOutputFile("output.json"),
                        },
                        expected: Reporter{
                                verbose:  true,
                                jsonOutput: true,
                                outputFile: "output.json",
                                findings: []types.Finding{},
                        },
                },
        }

        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        reporter := NewReporter(tc.options...)
                        assert.Equal(t, tc.expected.verbose, reporter.verbose)
                        assert.Equal(t, tc.expected.jsonOutput, reporter.jsonOutput)
                        assert.Equal(t, tc.expected.outputFile, reporter.outputFile)
                        assert.Empty(t, reporter.findings)
                })
        }
}

func TestSetFindings(t *testing.T) {
        // Create test findings
        findings := []types.Finding{
                {
                        Type:        "Test Type 1",
                        Severity:    "HIGH",
                        File:        "test1.go",
                        LineNumber:  10,
                        Content:     "test content 1",
                        Description: "Test description 1",
                        Vulnerable:  true,
                        Vulnerabilities: []types.Vulnerability{
                                {
                                        Type:        "Test Vulnerability",
                                        Severity:    "HIGH",
                                        Description: "Test vulnerability description",
                                },
                        },
                },
                {
                        Type:        "Test Type 2",
                        Severity:    "LOW",
                        File:        "test2.go",
                        LineNumber:  20,
                        Content:     "test content 2",
                        Description: "Test description 2",
                        Vulnerable:  false,
                },
        }
        
        // Create a reporter and set findings
        reporter := NewReporter()
        reporter.SetFindings(findings)
        
        // Check that findings were set correctly
        assert.Equal(t, findings, reporter.findings)
        assert.Len(t, reporter.findings, 2)
}

// TestGenerateJSONReport tests the GenerateJSONReport method
func TestGenerateJSONReport(t *testing.T) {
        // Create test findings
        findings := []types.Finding{
                {
                        Type:        "Test Type",
                        Severity:    "HIGH",
                        File:        "test.go",
                        LineNumber:  10,
                        Content:     "test content",
                        Description: "Test description",
                        Vulnerable:  true,
                        Vulnerabilities: []types.Vulnerability{
                                {
                                        Type:        "Test Vulnerability",
                                        Severity:    "HIGH",
                                        Description: "Test vulnerability description",
                                },
                        },
                },
        }
        
        // Create a reporter with JSON output
        reporter := NewReporter(WithJSONOutput(true))
        reporter.SetFindings(findings)
        
        // Generate the JSON report
        jsonReport := reporter.GenerateJSONReport()
        
        // Verify the JSON report can be parsed back to the original findings
        var parsedReport struct {
                Findings []types.Finding `json:"findings"`
                Summary  struct {
                        TotalFindings     int `json:"total_findings"`
                        VulnerableAssets  int `json:"vulnerable_assets"`
                        CriticalFindings  int `json:"critical_findings"`
                        HighFindings      int `json:"high_findings"`
                        MediumFindings    int `json:"medium_findings"`
                        LowFindings       int `json:"low_findings"`
                } `json:"summary"`
                Timestamp string `json:"timestamp"`
        }
        
        err := json.Unmarshal([]byte(jsonReport), &parsedReport)
        assert.NoError(t, err)
        
        assert.Equal(t, 1, parsedReport.Summary.TotalFindings)
        assert.Equal(t, 1, parsedReport.Summary.VulnerableAssets)
        assert.Equal(t, 0, parsedReport.Summary.CriticalFindings)
        assert.Equal(t, 1, parsedReport.Summary.HighFindings)
        assert.Equal(t, 0, parsedReport.Summary.MediumFindings)
        assert.Equal(t, 0, parsedReport.Summary.LowFindings)
        
        assert.Len(t, parsedReport.Findings, 1)
        assert.Equal(t, findings[0].Type, parsedReport.Findings[0].Type)
        assert.Equal(t, findings[0].Severity, parsedReport.Findings[0].Severity)
        assert.Equal(t, findings[0].File, parsedReport.Findings[0].File)
        assert.Equal(t, findings[0].LineNumber, parsedReport.Findings[0].LineNumber)
        assert.Equal(t, findings[0].Content, parsedReport.Findings[0].Content)
        assert.Equal(t, findings[0].Description, parsedReport.Findings[0].Description)
        assert.Equal(t, findings[0].Vulnerable, parsedReport.Findings[0].Vulnerable)
        assert.Len(t, parsedReport.Findings[0].Vulnerabilities, 1)
}

// TestWriteReportToFile tests writing the report to a file
func TestWriteReportToFile(t *testing.T) {
        // Create a temporary file for the test
        tempFile, err := os.CreateTemp("", "report-*.json")
        assert.NoError(t, err)
        defer os.Remove(tempFile.Name())
        tempFile.Close()
        
        // Create test findings
        findings := []types.Finding{
                {
                        Type:        "Test Type",
                        Severity:    "HIGH",
                        File:        "test.go",
                        LineNumber:  10,
                        Content:     "test content",
                        Description: "Test description",
                        Vulnerable:  true,
                },
        }
        
        // Create a reporter with JSON output and the temporary file
        reporter := NewReporter(
                WithJSONOutput(true),
                WithOutputFile(tempFile.Name()),
        )
        reporter.SetFindings(findings)
        
        // Write the report to the file
        err = reporter.WriteReportToFile()
        assert.NoError(t, err)
        
        // Read the file and check the content
        content, err := os.ReadFile(tempFile.Name())
        assert.NoError(t, err)
        assert.NotEmpty(t, content)
        
        // Verify the JSON content can be parsed
        var parsedReport struct {
                Findings []types.Finding `json:"findings"`
        }
        
        err = json.Unmarshal(content, &parsedReport)
        assert.NoError(t, err)
        assert.Len(t, parsedReport.Findings, 1)
        assert.Equal(t, findings[0].Type, parsedReport.Findings[0].Type)
}

// TestGenerateTextReport tests the generation of the text report
func TestGenerateTextReport(t *testing.T) {
        // Create test findings with different severities
        findings := []types.Finding{
                {
                        Type:        "API Key",
                        Severity:    "CRITICAL",
                        File:        "critical.go",
                        LineNumber:  10,
                        Content:     "critical content",
                        Description: "Critical description",
                        Vulnerable:  true,
                        Vulnerabilities: []types.Vulnerability{
                                {
                                        Type:        "Key Exposure",
                                        Severity:    "CRITICAL",
                                        Description: "Critical vulnerability",
                                        Reference:   "https://example.com/critical",
                                },
                        },
                },
                {
                        Type:        "Weak Hash",
                        Severity:    "HIGH",
                        File:        "high.go",
                        LineNumber:  20,
                        Content:     "high content",
                        Description: "High description",
                        Vulnerable:  true,
                        Vulnerabilities: []types.Vulnerability{
                                {
                                        Type:        "Weak Algorithm",
                                        Severity:    "HIGH",
                                        Description: "High vulnerability",
                                        Reference:   "https://example.com/high",
                                },
                        },
                },
                {
                        Type:        "Medium Risk",
                        Severity:    "MEDIUM",
                        File:        "medium.go",
                        LineNumber:  30,
                        Content:     "medium content",
                        Description: "Medium description",
                        Vulnerable:  true,
                },
                {
                        Type:        "Low Risk",
                        Severity:    "LOW",
                        File:        "low.go",
                        LineNumber:  40,
                        Content:     "low content",
                        Description: "Low description",
                        Vulnerable:  false,
                },
        }
        
        // Create both verbose and non-verbose reporters
        reporter := NewReporter(WithOutputFile("output.txt"))
        reporter.SetFindings(findings)
        
        verboseReporter := NewReporter(WithVerbose(true), WithOutputFile("output.txt"))
        verboseReporter.SetFindings(findings)
        
        // Generate text reports
        report := reporter.GenerateTextReport()
        verboseReport := verboseReporter.GenerateTextReport()
        
        // Basic verification of non-verbose report
        assert.NotEmpty(t, report)
        assert.Contains(t, report, "CRITICAL")
        assert.Contains(t, report, "API Key")
        assert.Contains(t, report, "critical.go")
        
        // The non-verbose report should mention findings are hidden
        assert.Contains(t, report, "and 2 more findings")
        
        // Verbose report should contain all findings
        assert.NotEmpty(t, verboseReport)
        assert.Contains(t, verboseReport, "CRITICAL")
        assert.Contains(t, verboseReport, "HIGH")
        assert.Contains(t, verboseReport, "MEDIUM")
        assert.Contains(t, verboseReport, "LOW")
        
        // It should not say findings are hidden
        assert.NotContains(t, verboseReport, "and 2 more findings")
}

// Test the conversion between scanner.Finding and types.Finding
func TestConvertFindings(t *testing.T) {
        // Create scanner findings
        scannerFindings := []scanner.Finding{
                {
                        Type:        "Test Type",
                        Severity:    "HIGH",
                        File:        "test.go",
                        LineNumber:  10,
                        Content:     "test content",
                        Description: "Test description",
                        Vulnerable:  true,
                        Vulnerabilities: []scanner.Vulnerability{
                                {
                                        Type:        "Test Vulnerability",
                                        Severity:    "HIGH",
                                        Description: "Test vulnerability description",
                                        Reference:   "https://example.com/reference",
                                },
                        },
                },
        }
        
        // Convert to types.Finding
        typesFindings := convertFindings(scannerFindings)
        
        assert.Len(t, typesFindings, 1)
        assert.Equal(t, scannerFindings[0].Type, typesFindings[0].Type)
        assert.Equal(t, scannerFindings[0].Severity, typesFindings[0].Severity)
        assert.Equal(t, scannerFindings[0].File, typesFindings[0].File)
        assert.Equal(t, scannerFindings[0].LineNumber, typesFindings[0].LineNumber)
        assert.Equal(t, scannerFindings[0].Content, typesFindings[0].Content)
        assert.Equal(t, scannerFindings[0].Description, typesFindings[0].Description)
        assert.Equal(t, scannerFindings[0].Vulnerable, typesFindings[0].Vulnerable)
        
        assert.Len(t, typesFindings[0].Vulnerabilities, 1)
        assert.Equal(t, scannerFindings[0].Vulnerabilities[0].Type, typesFindings[0].Vulnerabilities[0].Type)
        assert.Equal(t, scannerFindings[0].Vulnerabilities[0].Severity, typesFindings[0].Vulnerabilities[0].Severity)
        assert.Equal(t, scannerFindings[0].Vulnerabilities[0].Description, typesFindings[0].Vulnerabilities[0].Description)
        assert.Equal(t, scannerFindings[0].Vulnerabilities[0].Reference, typesFindings[0].Vulnerabilities[0].Reference)
}