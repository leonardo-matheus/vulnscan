package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	ColorPrimary   = lipgloss.Color("#00D4FF")
	ColorSecondary = lipgloss.Color("#7C3AED")
	ColorAccent    = lipgloss.Color("#F59E0B")
	ColorSuccess   = lipgloss.Color("#10B981")
	ColorError     = lipgloss.Color("#EF4444")
	ColorWarning   = lipgloss.Color("#F59E0B")
	ColorMuted     = lipgloss.Color("#6B7280")
	ColorWhite     = lipgloss.Color("#FFFFFF")
	ColorBgDark    = lipgloss.Color("#1E1E2E")
	ColorBgCard    = lipgloss.Color("#2D2D3F")
	ColorBorder    = lipgloss.Color("#4B5563")

	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1)

	StyleSubtitle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginBottom(1)

	StyleLogo = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true)

	StyleVersion = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Bold(true)

	StyleSuccess = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	StyleError = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	StyleWarning = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)

	StyleMuted = lipgloss.NewStyle().
			Foreground(ColorMuted)

	StyleHighlight = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true)

	StyleCard = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 2)

	StyleCardHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorPrimary).
				MarginBottom(1)

	StyleTableHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorPrimary).
				BorderBottom(true).
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(ColorBorder).
				PaddingBottom(1)

	StyleTableRow = lipgloss.NewStyle().
			Foreground(ColorWhite)

	StyleSeverityCritical = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FF0000")).
				Bold(true)

	StyleSeverityHigh = lipgloss.NewStyle().
				Foreground(ColorError).
				Bold(true)

	StyleSeverityMedium = lipgloss.NewStyle().
				Foreground(ColorWarning)

	StyleSeverityLow = lipgloss.NewStyle().
				Foreground(ColorMuted)
)

func RenderLogo() string {
	logo := `
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗  █████╗ ████████╗███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║██║  ███╗███████║   ██║   █████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║   ██║██╔══██║   ██║   ██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╔╝██║  ██║   ██║   ███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝`

	return StyleLogo.Render(logo)
}

func RenderBanner() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(RenderLogo())
	b.WriteString("\n")
	b.WriteString(StyleSubtitle.Render("  VulnGate — Vulnerability Scanner powered by Trivy"))
	b.WriteString("\n")
	b.WriteString(StyleMuted.Render("  Scan Java, Node.js, React, Vue.js projects for vulnerabilities"))
	b.WriteString("\n")

	return b.String()
}

func RenderVersion(version, commit, date, trivyVersion string) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(RenderLogo())
	b.WriteString("\n\n")

	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Padding(1, 3)

	content := StyleCardHeader.Render("VulnGate") + "\n\n" +
		StyleMuted.Render("Version:    ") + StyleVersion.Render(version) + "\n" +
		StyleMuted.Render("Commit:     ") + StyleHighlight.Render(commit) + "\n" +
		StyleMuted.Render("Built:      ") + StyleHighlight.Render(date) + "\n\n"

	if trivyVersion != "" {
		content += StyleMuted.Render("Trivy:      ") + StyleSuccess.Render("installed") + "\n"

		lines := strings.Split(trivyVersion, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				content += StyleMuted.Render("            ") + line + "\n"
			}
		}
	} else {
		content += StyleMuted.Render("Trivy:      ") + StyleError.Render("not installed") + "\n"
		content += StyleWarning.Render("            Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/") + "\n"
	}

	b.WriteString(card.Render(content))
	b.WriteString("\n")

	return b.String()
}

func RenderScanStart(target, scanType string) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(StyleCardHeader.Render("  Scan Information"))
	b.WriteString("\n\n")
	b.WriteString(StyleMuted.Render("  Target:    ") + StyleHighlight.Render(target) + "\n")
	b.WriteString(StyleMuted.Render("  Type:      ") + scanType + "\n")
	b.WriteString(StyleMuted.Render("  Status:    ") + StyleWarning.Render("scanning...") + "\n")
	b.WriteString("\n")

	return b.String()
}

func RenderScanComplete(exitCode int, output string) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(StyleCardHeader.Render("  Scan Results"))
	b.WriteString("\n\n")

	if exitCode > 0 {
		b.WriteString(StyleError.Render("  Vulnerabilities found!"))
		b.WriteString("\n")
		b.WriteString(StyleMuted.Render(fmt.Sprintf("  Exit code: %d", exitCode)))
	} else {
		b.WriteString(StyleSuccess.Render("  No vulnerabilities found"))
		b.WriteString("\n")
		b.WriteString(StyleMuted.Render("  Exit code: 0"))
	}

	b.WriteString("\n")

	return b.String()
}

func RenderError(msg string) string {
	return StyleError.Render("Error: " + msg)
}

func RenderWarning(msg string) string {
	return StyleWarning.Render("Warning: " + msg)
}

func RenderSuccess(msg string) string {
	return StyleSuccess.Render(msg)
}

func RenderMuted(msg string) string {
	return StyleMuted.Render(msg)
}

func RenderHighlight(msg string) string {
	return StyleHighlight.Render(msg)
}

func RenderProgressBar(label string, percent int) string {
	width := 40
	filled := (width * percent) / 100
	empty := width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	styledBar := lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Render(bar)

	return fmt.Sprintf("%s %s %d%%", label, styledBar, percent)
}

func RenderTable(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return ""
	}

	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	var b strings.Builder

	for i, h := range headers {
		b.WriteString(StyleTableHeader.Render(
			fmt.Sprintf("%-*s", colWidths[i], h),
		))
		if i < len(headers)-1 {
			b.WriteString("  ")
		}
	}
	b.WriteString("\n")

	separator := ""
	for i, w := range colWidths {
		separator += strings.Repeat("─", w)
		if i < len(colWidths)-1 {
			separator += "  "
		}
	}
	b.WriteString(StyleMuted.Render(separator))
	b.WriteString("\n")

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) {
				b.WriteString(fmt.Sprintf("%-*s", colWidths[i], cell))
			}
			if i < len(row)-1 {
				b.WriteString("  ")
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

func RenderBox(title, content string) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Padding(1, 2).
		Width(60)

	header := StyleCardHeader.Render(title)
	fullContent := header + "\n" + content

	return box.Render(fullContent)
}

func RenderDivider() string {
	return StyleMuted.Render(strings.Repeat("─", 60))
}

func RenderSpacer() string {
	return "\n"
}

func RenderCommandHelp(cmd, description, examples string) string {
	var b strings.Builder

	b.WriteString(StyleCardHeader.Render(cmd))
	b.WriteString("\n")
	b.WriteString(StyleMuted.Render(description))
	b.WriteString("\n")

	if examples != "" {
		b.WriteString("\n")
		b.WriteString(StyleHighlight.Render("Examples:"))
		b.WriteString("\n")
		b.WriteString(StyleMuted.Render(examples))
	}

	return b.String()
}

func RenderSeverityBadge(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return StyleSeverityCritical.Render("● CRITICAL")
	case "HIGH":
		return StyleSeverityHigh.Render("● HIGH")
	case "MEDIUM":
		return StyleSeverityMedium.Render("● MEDIUM")
	case "LOW":
		return StyleSeverityLow.Render("● LOW")
	default:
		return severity
	}
}
