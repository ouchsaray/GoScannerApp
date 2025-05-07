package notifier

import (
        "encoding/json"
        "fmt"
        "strings"
        "time"

        "github.com/slack-go/slack"
        "github.com/yourusername/cryptoscan/pkg/types"
)

// SlackNotifier handles sending notifications to Slack
type SlackNotifier struct {
        webhookURL  string
        channel     string
        username    string
        iconEmoji   string
        environment string
}

// NewSlackNotifier creates a new Slack notifier
func NewSlackNotifier(webhookURL, channel, username, iconEmoji, environment string) *SlackNotifier {
        if username == "" {
                username = "CryptoScan"
        }
        if iconEmoji == "" {
                iconEmoji = ":lock:"
        }
        if environment == "" {
                environment = "production"
        }

        return &SlackNotifier{
                webhookURL:  webhookURL,
                channel:     channel,
                username:    username,
                iconEmoji:   iconEmoji,
                environment: environment,
        }
}

// NotifyFindings sends a notification about findings to Slack
func (s *SlackNotifier) NotifyFindings(findings []types.Finding, targetPath string) error {
        if s.webhookURL == "" {
                return fmt.Errorf("Slack webhook URL is required")
        }

        // Count findings by severity
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
        
        // Set color based on highest severity
        var color string
        if criticalCount > 0 {
                color = "danger"
        } else if highCount > 0 {
                color = "warning"
        } else if mediumCount > 0 {
                color = "#FFCC00"
        } else {
                color = "good"
        }
        
        // Create message attachment
        attachment := slack.Attachment{
                Color:      color,
                Title:      "CryptoScan Security Report",
                TitleLink:  "",
                AuthorName: "CryptoScan",
                AuthorIcon: "https://raw.githubusercontent.com/yourusername/cryptoscan/main/logo.png",
                Text:       fmt.Sprintf("Security scan completed for *%s*", targetPath),
                Fields: []slack.AttachmentField{
                        {
                                Title: "Critical",
                                Value: fmt.Sprintf("%d", criticalCount),
                                Short: true,
                        },
                        {
                                Title: "High",
                                Value: fmt.Sprintf("%d", highCount),
                                Short: true,
                        },
                        {
                                Title: "Medium",
                                Value: fmt.Sprintf("%d", mediumCount),
                                Short: true,
                        },
                        {
                                Title: "Low",
                                Value: fmt.Sprintf("%d", lowCount),
                                Short: true,
                        },
                        {
                                Title: "Environment",
                                Value: s.environment,
                                Short: true,
                        },
                        {
                                Title: "Total Findings",
                                Value: fmt.Sprintf("%d", len(findings)),
                                Short: true,
                        },
                },
                Footer:     "CryptoScan Security Scanner",
                FooterIcon: "https://raw.githubusercontent.com/yourusername/cryptoscan/main/logo.png",
                Ts:         json.Number(fmt.Sprintf("%d", time.Now().Unix())),
        }
        
        // Add top findings (up to 5)
        if len(findings) > 0 {
                // Sort findings by severity (bubble sort for simplicity)
                sortedFindings := make([]types.Finding, len(findings))
                copy(sortedFindings, findings)
                
                for i := 0; i < len(sortedFindings); i++ {
                        for j := i + 1; j < len(sortedFindings); j++ {
                                if getSeverityRank(sortedFindings[i].Severity) < getSeverityRank(sortedFindings[j].Severity) {
                                        sortedFindings[i], sortedFindings[j] = sortedFindings[j], sortedFindings[i]
                                }
                        }
                }
                
                numToShow := 5
                if numToShow > len(sortedFindings) {
                        numToShow = len(sortedFindings)
                }
                
                var topFindingsText strings.Builder
                for i := 0; i < numToShow; i++ {
                        finding := sortedFindings[i]
                        vulnText := ""
                        if len(finding.Vulnerabilities) > 0 {
                                vulnText = fmt.Sprintf(" - %s: %s", finding.Vulnerabilities[0].Type, finding.Vulnerabilities[0].Description)
                        }
                        
                        topFindingsText.WriteString(fmt.Sprintf("• *[%s]* %s in `%s`%s\n", 
                                finding.Severity, finding.Type, finding.File, vulnText))
                }
                
                if len(sortedFindings) > numToShow {
                        topFindingsText.WriteString(fmt.Sprintf("• _... and %d more findings_\n", len(sortedFindings)-numToShow))
                }
                
                attachment.Fields = append(attachment.Fields, slack.AttachmentField{
                        Title: "Top Findings",
                        Value: topFindingsText.String(),
                        Short: false,
                })
        }
        
        // Define message payload
        msg := slack.WebhookMessage{
                Username:    s.username,
                IconEmoji:   s.iconEmoji,
                Channel:     s.channel,
                Attachments: []slack.Attachment{attachment},
        }
        
        // Send message
        return slack.PostWebhook(s.webhookURL, &msg)
}

// getSeverityRank returns a numeric rank for severity (higher is more severe)
func getSeverityRank(severity string) int {
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