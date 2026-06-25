package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	SummaryBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(ColorPrimary).
			Padding(1, 2)

	SummaryHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1)

	SummaryRow = lipgloss.NewStyle().
			Foreground(ColorWhite)

	SummaryLabel = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Width(20)

	SummaryValue = lipgloss.NewStyle().
			Foreground(ColorWhite).
			Bold(true)

	SeverityCriticalBadge = lipgloss.NewStyle().
				Background(lipgloss.Color("#DC2626")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Bold(true).
				Padding(0, 1)

	SeverityHighBadge = lipgloss.NewStyle().
				Background(lipgloss.Color("#EF4444")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Bold(true).
				Padding(0, 1)

	SeverityMediumBadge = lipgloss.NewStyle().
				Background(lipgloss.Color("#F59E0B")).
				Foreground(lipgloss.Color("#000000")).
				Bold(true).
				Padding(0, 1)

	SeverityLowBadge = lipgloss.NewStyle().
				Background(lipgloss.Color("#6B7280")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Padding(0, 1)

	SeverityInfoBadge = lipgloss.NewStyle().
				Background(lipgloss.Color("#3B82F6")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Padding(0, 1)

	SuccessBig = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true).
			MarginTop(1)

	ErrorBig = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true).
			MarginTop(1)

	WarningBig = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true).
			MarginTop(1)
)

type ScanSummary struct {
	Target          string
	ScanType        string
	Duration        string
	ExitCode        int
	VulnTotal       int
	VulnCritical    int
	VulnHigh        int
	VulnMedium      int
	VulnLow         int
	VulnUnknown     int
	MisconfigTotal  int
	MisconfigHigh   int
	MisconfigCritical int
	SecretTotal     int
	FilesScanned    int
	OutputPath      string
	SARIFPath       string
}

func RenderScanSummary(s ScanSummary) string {
	var b strings.Builder

	b.WriteString("\n")

	if s.ExitCode > 0 {
		b.WriteString(ErrorBig.Render("  ✘ Vulnerabilities detected"))
	} else {
		b.WriteString(SuccessBig.Render("  ✔ No vulnerabilities found"))
	}

	b.WriteString("\n\n")

	cardLines := []string{}

	cardLines = append(cardLines, SummaryHeader.Render("  Scan Summary"))
	cardLines = append(cardLines, "")
	cardLines = append(cardLines, fmt.Sprintf("  %s %s", SummaryLabel.Render("Target:"), SummaryValue.Render(truncate(s.Target, 50))))
	cardLines = append(cardLines, fmt.Sprintf("  %s %s", SummaryLabel.Render("Type:"), SummaryValue.Render(s.ScanType)))
	cardLines = append(cardLines, fmt.Sprintf("  %s %s", SummaryLabel.Render("Duration:"), SummaryValue.Render(s.Duration)))
	cardLines = append(cardLines, "")

	if s.VulnTotal > 0 || s.MisconfigTotal > 0 || s.SecretTotal > 0 {
		cardLines = append(cardLines, SummaryHeader.Render("  Findings"))
		cardLines = append(cardLines, "")

		if s.VulnTotal > 0 {
			cardLines = append(cardLines, fmt.Sprintf("  %s %s",
				SummaryLabel.Render("Vulnerabilities:"),
				SummaryValue.Render(fmt.Sprintf("%d", s.VulnTotal))))
			cardLines = append(cardLines, renderSeverityBadges(s.VulnCritical, s.VulnHigh, s.VulnMedium, s.VulnLow, s.VulnUnknown))
			cardLines = append(cardLines, "")
		}

		if s.MisconfigTotal > 0 {
			cardLines = append(cardLines, fmt.Sprintf("  %s %s",
				SummaryLabel.Render("Misconfigurations:"),
				SummaryValue.Render(fmt.Sprintf("%d", s.MisconfigTotal))))
			if s.MisconfigCritical > 0 || s.MisconfigHigh > 0 {
				cardLines = append(cardLines, renderMisconfigBadges(s.MisconfigCritical, s.MisconfigHigh))
			}
			cardLines = append(cardLines, "")
		}

		if s.SecretTotal > 0 {
			cardLines = append(cardLines, fmt.Sprintf("  %s %s",
				SummaryLabel.Render("Secrets:"),
				SeverityCriticalBadge.Render(fmt.Sprintf(" %d ", s.SecretTotal))))
			cardLines = append(cardLines, "")
		}
	} else {
		cardLines = append(cardLines, fmt.Sprintf("  %s", SummaryLabel.Render("Status:")))
		cardLines = append(cardLines, fmt.Sprintf("  %s", SuccessBig.Render("No findings detected")))
		cardLines = append(cardLines, "")
	}

	if s.OutputPath != "" {
		cardLines = append(cardLines, fmt.Sprintf("  %s %s", SummaryLabel.Render("SARIF report:"), StyleHighlight.Render(s.OutputPath)))
		cardLines = append(cardLines, "")
	}

	if s.SARIFPath != "" && s.SARIFPath != s.OutputPath {
		cardLines = append(cardLines, fmt.Sprintf("  %s %s", SummaryLabel.Render("JSON report:"), StyleHighlight.Render(s.SARIFPath)))
		cardLines = append(cardLines, "")
	}

	content := strings.Join(cardLines, "\n")
	b.WriteString(SummaryBox.Render(content))
	b.WriteString("\n")

	return b.String()
}

func renderSeverityBadges(critical, high, medium, low, unknown int) string {
	var parts []string

	if critical > 0 {
		parts = append(parts, SeverityCriticalBadge.Render(fmt.Sprintf(" CRITICAL: %d ", critical)))
	}
	if high > 0 {
		parts = append(parts, SeverityHighBadge.Render(fmt.Sprintf(" HIGH: %d ", high)))
	}
	if medium > 0 {
		parts = append(parts, SeverityMediumBadge.Render(fmt.Sprintf(" MEDIUM: %d ", medium)))
	}
	if low > 0 {
		parts = append(parts, SeverityLowBadge.Render(fmt.Sprintf(" LOW: %d ", low)))
	}
	if unknown > 0 {
		parts = append(parts, SeverityInfoBadge.Render(fmt.Sprintf(" UNKNOWN: %d ", unknown)))
	}

	return "            " + strings.Join(parts, " ")
}

func renderMisconfigBadges(critical, high int) string {
	var parts []string

	if critical > 0 {
		parts = append(parts, SeverityCriticalBadge.Render(fmt.Sprintf(" CRITICAL: %d ", critical)))
	}
	if high > 0 {
		parts = append(parts, SeverityHighBadge.Render(fmt.Sprintf(" HIGH: %d ", high)))
	}

	return "            " + strings.Join(parts, " ")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
