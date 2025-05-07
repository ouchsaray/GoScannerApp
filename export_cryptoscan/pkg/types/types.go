package types

// Finding represents a detected cryptographic asset
type Finding struct {
	File            string         `json:"file"`
	Type            string         `json:"type"`
	Description     string         `json:"description"`
	LineNumber      int            `json:"lineNumber"`
	Content         string         `json:"content"`
	Severity        string         `json:"severity"`
	Vulnerable      bool           `json:"vulnerable"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Vulnerability represents a detected security issue
type Vulnerability struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Reference   string `json:"reference"`
}
