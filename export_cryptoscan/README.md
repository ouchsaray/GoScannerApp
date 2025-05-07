# CryptoScan

A Go-based CLI tool that scans GitHub repositories and local directories for cryptographic assets and vulnerabilities.

## Features

- Detect cryptographic assets (private/public keys, certificates, credentials, tokens)
- Identify cryptographic vulnerabilities and security issues
- Provide actionable security recommendations
- Filter results by severity, file pattern, or finding type
- Scan both GitHub repositories and local files/directories
- Generate formatted reports (text or JSON)

## Installation

### Prerequisites

- Go 1.16 or higher

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/cryptoscan.git
cd cryptoscan

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

## Test Samples

The repository includes test samples with mock cryptographic assets in the `test_samples` directory. You can use these to test the scanner:

```bash
./cryptoscan scan ./test_samples
```

## GitHub Actions Integration

CryptoScan can be integrated into your CI/CD pipeline using GitHub Actions. See the `.github/workflows` directory for example workflows.

## License

[MIT License](LICENSE)