# CryptoScan

A sophisticated Go-based CLI tool for comprehensive cryptographic asset and vulnerability scanning across multiple Git providers and local repositories.

## Features

### Scanning Capabilities
- **Advanced Asset Detection**: Automatically identifies a wide range of cryptographic assets including:
  - Public/private keys (RSA, DSA, EC)
  - Certificates and certificate chains
  - Hardcoded credentials and tokens (AWS, Google Cloud, GitHub, JWT)
  - API keys and secrets
  - Encoded cryptographic material (Base64, Hex)

### Security Analysis
- **Vulnerability Assessment**: Performs deep analysis to detect:
  - Weak cryptographic algorithms and modes
  - Insufficient key lengths
  - Insecure implementations
  - Key exposure issues
  - Hardcoded credentials in source code
  - Configuration vulnerabilities

### Interactive Dashboard
- **Visual Reporting**: Rich terminal-based dashboard with:
  - Color-coded severity indicators with advanced formatting
  - Interactive visual distribution graphs and proportional bar charts
  - Comprehensive risk summaries with weighted scoring
  - Filterable findings display with actionable recommendations
  - Advanced statistics and metrics with percentage distributions
  - Custom ASCII art logo and visually appealing layout

### Usability Features
- **Multi-stage Progress Tracking**: Animated spinners with real-time status updates
- **Flexible Filtering**: Filter by severity, file type, finding category, and more
- **Performance Metrics**: Detailed processing statistics during scans
- **Actionable Recommendations**: Context-specific remediation guidance for each finding

### Integration Capabilities
- **Multiple Git Providers**: Support for GitHub, GitLab, and Bitbucket repositories
- **Slack Notifications**: Real-time vulnerability alerts via Slack webhooks
- **GitHub Actions**: Automated scanning in CI/CD pipelines
- **Multiple Output Formats**: Support for text, JSON, and dashboard output modes
- **Non-blocking Scans**: Background processing for large repositories
- **Provider Detection**: Automatic Git provider detection from URLs and local repositories

## Installation

### Prerequisites

- Go 1.16 or higher

### Building from Source

```bash
# Clone the repository
git clone https://github.com/ouchsaray/GoScannerApp.git
cd GoScannerApp

# Build the binary
go build -o cryptoscan

# Make the binary executable (important for Unix/Linux/macOS)
chmod +x cryptoscan

# Install globally (optional)
# This will install to your $GOPATH/bin directory
go install

# If you install globally, ensure $GOPATH/bin is in your PATH
# For bash, you can add this to your ~/.bashrc or ~/.bash_profile:
# export PATH=$PATH:$GOPATH/bin
```

### Troubleshooting "Command Not Found" Errors

If you encounter a "command not found" error when trying to run `./cryptoscan`, try the following:

1. **Make sure you're in the correct directory**:
   ```bash
   # Navigate to the directory containing the cryptoscan binary
   cd /path/to/GoScannerApp
   ```

2. **Make the binary executable** (if you haven't already):
   ```bash
   chmod +x cryptoscan
   ```

3. **Use the full path to run the binary**:
   ```bash
   # Current directory
   ./cryptoscan scan ./test_samples
   
   # Or with absolute path
   /path/to/GoScannerApp/cryptoscan scan ./test_samples
   ```

4. **Verify the binary exists and is executable**:
   ```bash
   ls -la cryptoscan
   # Should show something like: -rwxr-xr-x 1 user group size date cryptoscan
   ```

5. **Rebuild if necessary**:
   ```bash
   go build -o cryptoscan
   chmod +x cryptoscan
   ```

## Usage

### Basic Usage

```bash
# Scan a GitHub repository
./cryptoscan scan https://github.com/owner/repo

# Scan a GitLab repository
./cryptoscan scan https://gitlab.com/owner/repo

# Scan a Bitbucket repository
./cryptoscan scan https://bitbucket.org/owner/repo

# Scan a local directory
./cryptoscan scan ./path/to/directory

# Scan a specific file
./cryptoscan scan ./path/to/file.yml

# Generate interactive dashboard
./cryptoscan dashboard ./path/to/directory

# Generate dashboard for a GitLab repository
./cryptoscan dashboard https://gitlab.com/owner/repo
```

### Options

```
Usage:
  cryptoscan scan [repository URL or local path] [flags]

Flags:
  -h, --help                  help for scan
      --file-pattern string   Filter files by pattern (e.g., '*.js' or 'src/*')
      --max int               Maximum number of results to show (0 for all)
  -o, --output string         Output format: text or json (default "text")
      --only-vuln             Show only findings with vulnerabilities
      --severity string       Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
      --skip-libs             Skip scanning libraries and vendor directories
      --skip-vuln             Skip vulnerability check
      --type string           Filter by finding type (e.g., 'Private Key' or 'AWS')
  -v, --verbose               Enable verbose output
```

### Examples

```bash
# Verbose output with more details
./cryptoscan scan https://github.com/example/repo -v

# Filter by severity level
./cryptoscan scan ./my-project --severity HIGH

# Only show findings with vulnerabilities
./cryptoscan scan ./my-project --only-vuln

# Skip libraries and vendor directories
./cryptoscan scan https://github.com/example/repo --skip-libs

# Filter by file pattern
./cryptoscan scan ./my-project --file-pattern "*.js"

# Filter by finding type
./cryptoscan scan ./my-project --type "Private Key"

# Output as JSON
./cryptoscan scan ./my-project -o json

# Limit number of results
./cryptoscan scan ./my-project --max 10
```

### Dashboard Command

The dashboard command provides an enhanced interactive visualization of scan results with advanced UI features:

- **Interactive Risk Assessment**: Color-coded risk scores with weighted severity calculations
- **Visual Charts**: Proportional bar charts for severity and finding type distribution
- **Detailed Finding Analysis**: Comprehensive view of vulnerabilities with extended metadata
- **Smart Recommendations**: Context-aware security recommendations for each finding
- **Dynamic Type Distribution**: Visual representation of finding categories with proportional bars
- **Provider-Based Formatting**: Customized display based on Git provider or local repository

```
Usage:
  cryptoscan dashboard [repository URL or local path] [flags]

Flags:
  -h, --help                  help for dashboard
      --file-pattern string   Filter files by pattern (e.g., '*.js' or 'src/*')
      --max int               Maximum number of results to show (0 for all)
      --only-vuln             Show only findings with vulnerabilities
      --severity string       Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
      --skip-libs             Skip scanning libraries and vendor directories
      --type string           Filter by finding type (e.g., 'Private Key' or 'AWS')
  -v, --verbose               Enable verbose output
```

Dashboard examples:

```bash
# Generate dashboard for a local directory
./cryptoscan dashboard ./my-project

# Generate dashboard for a GitHub repository
./cryptoscan dashboard https://github.com/example/repo

# Generate dashboard for a GitLab repository
./cryptoscan dashboard https://gitlab.com/example/repo

# Generate dashboard for a Bitbucket repository
./cryptoscan dashboard https://bitbucket.org/example/repo

# Filter by severity in dashboard view
./cryptoscan dashboard ./my-project --severity HIGH

# Show only items with vulnerabilities
./cryptoscan dashboard ./my-project --only-vuln

# Filter items by type in dashboard
./cryptoscan dashboard ./my-project --type "AWS"
```

## Generating Reports

CryptoScan provides multiple ways to generate and customize security reports, each with different visualization options and output formats.

### Report Types

1. **Text Reports** - Standard console output with finding details
2. **JSON Reports** - Structured data for programmatic processing
3. **Interactive Dashboard** - Enhanced visual representation with charts and risk scoring
4. **Slack Notifications** - Real-time alerts for critical findings

### Generating Text Reports

Text reports provide detailed information about detected findings with color-coded severity levels:

```bash
# Basic text report
./cryptoscan scan ./test_samples

# Verbose text report with all details
./cryptoscan scan ./test_samples --verbose

# Text report with severity filtering
./cryptoscan scan ./test_samples --severity HIGH

# Text report focusing only on findings with vulnerabilities
./cryptoscan scan ./test_samples --only-vuln

# Text report with type filtering
./cryptoscan scan ./test_samples --type "AWS"

# Text report with combined filters
./cryptoscan scan ./test_samples --severity HIGH --type "API Key" --file-pattern "*.js"
```

### Generating JSON Reports

JSON reports provide structured data that can be easily processed by other tools:

```bash
# Basic JSON report
./cryptoscan scan ./test_samples -o json > report.json

# Filtered JSON report
./cryptoscan scan ./test_samples -o json --severity CRITICAL > critical_issues.json

# Complete JSON report with all details
./cryptoscan scan ./test_samples -o json --verbose > full_report.json
```

### Generating Interactive Dashboard Reports

The dashboard provides a rich, visual representation of your security findings:

```bash
# Basic dashboard for local directory
./cryptoscan dashboard ./test_samples

# Dashboard for a remote repository
./cryptoscan dashboard https://github.com/owner/repo

# Filtered dashboard showing only critical issues
./cryptoscan dashboard ./test_samples --severity CRITICAL

# Dashboard with verbose output showing extended details
./cryptoscan dashboard ./test_samples --verbose
```

### Saving Reports to Files

You can save reports to files for later reference:

```bash
# Save text report to file
./cryptoscan scan ./test_samples > scan_report.txt

# Save JSON report to file
./cryptoscan scan ./test_samples -o json > scan_report.json

# Save filtered report to file
./cryptoscan scan ./test_samples --severity HIGH > high_severity_report.txt
```

### Report Customization Options

All report types support these customization options:

| Option | Description | Example |
|--------|-------------|---------|
| `--severity` | Filter by minimum severity level | `--severity HIGH` |
| `--type` | Filter by finding type | `--type "API Key"` |
| `--file-pattern` | Filter by file pattern | `--file-pattern "*.js"` |
| `--max` | Limit number of results | `--max 10` |
| `--only-vuln` | Show only vulnerable findings | `--only-vuln` |
| `--skip-libs` | Skip scanning library directories | `--skip-libs` |
| `--verbose` | Show extended details | `--verbose` |

## Test Samples

The repository includes test samples with mock cryptographic assets in the `test_samples` directory. You can use these to test the scanner and dashboard:

```bash
# Scan with standard output
./cryptoscan scan ./test_samples

# View results in interactive dashboard
./cryptoscan dashboard ./test_samples

# Generate JSON report from test samples
./cryptoscan scan ./test_samples -o json > test_report.json
```

## Integrations and Advanced Features

### CI/CD Integration

CryptoScan can be integrated into your CI/CD pipeline:

- **GitHub Actions**: Automatic scanning using the included workflow in `.github/workflows` directory
- **GitLab CI/CD**: Can be configured to scan repositories in GitLab pipelines
- **Bitbucket Pipelines**: Support for scanning in Bitbucket Pipelines

### Slack Notifications

CryptoScan supports real-time notifications to Slack when vulnerabilities are detected. Configure a Slack webhook URL to receive alerts:

```bash
# Set your Slack webhook URL as an environment variable
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Run scan with Slack notifications enabled
./cryptoscan scan ./my-project --notify-slack
```

### Real-time Progress Tracking

CryptoScan includes advanced progress tracking with animated spinners:

1. **Single-stage Progress**: Visualizes the current operation with animated indicators
2. **Multi-stage Progress**: Tracks and displays progress across multiple scanning phases
3. **Success/Error States**: Provides visual feedback on operation completion status
4. **Performance Metrics**: Shows detailed processing statistics during scan operations

## Testing

CryptoScan includes comprehensive tests for all major components. You can run these tests to verify that the tool is working correctly.

### Running Tests

To run all the tests in the project:

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test ./internal/scanner
go test ./internal/reporter
go test ./cmd

# Generate test coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Using the Test Script

The project includes a `run_tests.sh` script that automates the testing process:

```bash
# Make the script executable
chmod +x run_tests.sh

# Run all tests
./run_tests.sh

# Run tests for a specific component
./run_tests.sh scanner
```

### Using Make for Testing

The included Makefile provides shortcuts for common testing operations:

```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Generate test coverage report
make coverage

# Clean up test artifacts
make clean
```

### Test Samples

The `test_samples` directory contains files with various cryptographic assets and vulnerabilities for testing:

- **apikeys.txt**: Contains mock API keys and credentials
- **config.yml**: Contains configuration with insecure settings
- **insecure_crypto.go**: Contains insecure cryptographic implementations
- **low_risk_examples.go**: Contains examples of low severity issues
- **only_low_severity.go**: Contains only low severity issues for testing filters

You can use these files to test specific detection capabilities:

```bash
# Test detection of specific vulnerabilities
./cryptoscan scan ./test_samples/insecure_crypto.go

# Test with low severity issues only
./cryptoscan scan ./test_samples/only_low_severity.go

# Test filtering by severity
./cryptoscan scan ./test_samples --severity HIGH
```

## License

[MIT License](LICENSE)