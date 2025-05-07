# CryptoScan

A sophisticated Go-based CLI tool for comprehensive cryptographic asset and vulnerability scanning across code repositories.

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
  - Color-coded severity indicators
  - Visual distribution graphs
  - Interactive vulnerability details
  - Filterable findings display
  - Summary statistics and metrics

### Usability Features
- **Multi-stage Progress Tracking**: Animated spinners with real-time status updates
- **Flexible Filtering**: Filter by severity, file type, finding category, and more
- **Performance Metrics**: Detailed processing statistics during scans
- **Actionable Recommendations**: Context-specific remediation guidance for each finding

### Integration Capabilities
- **Slack Notifications**: Real-time vulnerability alerts via Slack webhooks
- **GitHub Actions**: Automated scanning in CI/CD pipelines
- **Multiple Output Formats**: Support for text, JSON, and dashboard output modes
- **Non-blocking Scans**: Background processing for large repositories

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

# Install (optional)
go install
```

## Usage

### Basic Usage

```bash
# Scan a GitHub repository
./cryptoscan scan https://github.com/owner/repo

# Scan a local directory
./cryptoscan scan ./path/to/directory

# Scan a specific file
./cryptoscan scan ./path/to/file.yml

# Generate interactive dashboard
./cryptoscan dashboard ./path/to/directory
```

### Options

```
Usage:
  cryptoscan scan [github repository URL or local path] [flags]

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

The dashboard command provides an interactive visualization of scan results with additional filtering options:

```
Usage:
  cryptoscan dashboard [github repository URL or local path] [flags]

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

# Filter by severity in dashboard view
./cryptoscan dashboard ./my-project --severity HIGH

# Show only items with vulnerabilities
./cryptoscan dashboard ./my-project --only-vuln

# Filter items by type in dashboard
./cryptoscan dashboard ./my-project --type "AWS"
```

## Test Samples

The repository includes test samples with mock cryptographic assets in the `test_samples` directory. You can use these to test the scanner and dashboard:

```bash
# Scan with standard output
./cryptoscan scan ./test_samples

# View results in interactive dashboard
./cryptoscan dashboard ./test_samples
```

## Integrations and Advanced Features

### GitHub Actions Integration

CryptoScan can be integrated into your CI/CD pipeline using GitHub Actions. See the `.github/workflows` directory for example workflows.

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

## License

[MIT License](LICENSE)