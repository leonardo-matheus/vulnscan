package ui

import (
	"strings"
	"testing"
)

func TestRenderLogo(t *testing.T) {
	logo := RenderLogo()
	if logo == "" {
		t.Error("RenderLogo() returned empty string")
	}
	if !strings.Contains(logo, "██╗") && !strings.Contains(logo, "VULNGATE") {
		t.Error("RenderLogo() does not contain expected ASCII art")
	}
}

func TestRenderBanner(t *testing.T) {
	banner := RenderBanner()
	if banner == "" {
		t.Error("RenderBanner() returned empty string")
	}
	if !strings.Contains(banner, "VulnGate") {
		t.Error("RenderBanner() does not contain 'VulnGate'")
	}
}

func TestRenderVersion(t *testing.T) {
	version := RenderVersion("1.0.0", "abc123", "2024-01-01", "trivy 0.50.0")
	if version == "" {
		t.Error("RenderVersion() returned empty string")
	}
	if !strings.Contains(version, "1.0.0") {
		t.Error("RenderVersion() does not contain version")
	}
	if !strings.Contains(version, "abc123") {
		t.Error("RenderVersion() does not contain commit")
	}
}

func TestRenderVersion_NoTrivy(t *testing.T) {
	version := RenderVersion("1.0.0", "abc123", "2024-01-01", "")
	if !strings.Contains(version, "not installed") {
		t.Error("RenderVersion() should show 'not installed' when trivyVersion is empty")
	}
}

func TestRenderScanStart(t *testing.T) {
	scan := RenderScanStart("/path/to/project", "filesystem")
	if scan == "" {
		t.Error("RenderScanStart() returned empty string")
	}
	if !strings.Contains(scan, "/path/to/project") {
		t.Error("RenderScanStart() does not contain target path")
	}
	if !strings.Contains(scan, "filesystem") {
		t.Error("RenderScanStart() does not contain scan type")
	}
}

func TestRenderScanComplete(t *testing.T) {
	scan := RenderScanComplete(0, "")
	if scan == "" {
		t.Error("RenderScanComplete() returned empty string")
	}
	if !strings.Contains(scan, "No vulnerabilities found") {
		t.Error("RenderScanComplete(0) should show 'No vulnerabilities found'")
	}

	scan = RenderScanComplete(1, "")
	if !strings.Contains(scan, "Vulnerabilities found") {
		t.Error("RenderScanComplete(1) should show 'Vulnerabilities found'")
	}
}

func TestRenderError(t *testing.T) {
	err := RenderError("something failed")
	if !strings.Contains(err, "something failed") {
		t.Error("RenderError() does not contain error message")
	}
}

func TestRenderWarning(t *testing.T) {
	warn := RenderWarning("be careful")
	if !strings.Contains(warn, "be careful") {
		t.Error("RenderWarning() does not contain warning message")
	}
}

func TestRenderSuccess(t *testing.T) {
	success := RenderSuccess("all good")
	if !strings.Contains(success, "all good") {
		t.Error("RenderSuccess() does not contain success message")
	}
}

func TestRenderMuted(t *testing.T) {
	muted := RenderMuted("faint text")
	if !strings.Contains(muted, "faint text") {
		t.Error("RenderMuted() does not contain text")
	}
}

func TestRenderHighlight(t *testing.T) {
	highlight := RenderHighlight("important")
	if !strings.Contains(highlight, "important") {
		t.Error("RenderHighlight() does not contain text")
	}
}

func TestRenderSeverityBadge(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		badge := RenderSeverityBadge(tt.input)
		if !strings.Contains(badge, tt.expected) {
			t.Errorf("RenderSeverityBadge(%q) = %q, want containing %q", tt.input, badge, tt.expected)
		}
	}
}

func TestRenderDivider(t *testing.T) {
	divider := RenderDivider()
	if divider == "" {
		t.Error("RenderDivider() returned empty string")
	}
}

func TestRenderSpacer(t *testing.T) {
	spacer := RenderSpacer()
	if spacer != "\n" {
		t.Errorf("RenderSpacer() = %q, want %q", spacer, "\n")
	}
}

func TestRenderTable(t *testing.T) {
	headers := []string{"Name", "Version", "Severity"}
	rows := [][]string{
		{"log4j", "2.14.1", "CRITICAL"},
		{"spring-core", "5.3.0", "HIGH"},
	}

	table := RenderTable(headers, rows)
	if table == "" {
		t.Error("RenderTable() returned empty string")
	}
	if !strings.Contains(table, "Name") {
		t.Error("RenderTable() does not contain header")
	}
	if !strings.Contains(table, "log4j") {
		t.Error("RenderTable() does not contain row data")
	}
}

func TestRenderTable_Empty(t *testing.T) {
	table := RenderTable([]string{}, [][]string{})
	if table != "" {
		t.Error("RenderTable() should return empty for empty input")
	}
}

func TestRenderBox(t *testing.T) {
	box := RenderBox("Title", "Content")
	if box == "" {
		t.Error("RenderBox() returned empty string")
	}
	if !strings.Contains(box, "Title") {
		t.Error("RenderBox() does not contain title")
	}
	if !strings.Contains(box, "Content") {
		t.Error("RenderBox() does not contain content")
	}
}

func TestRenderCommandHelp(t *testing.T) {
	help := RenderCommandHelp("scan", "Scan targets", "  vulngate scan fs .")
	if help == "" {
		t.Error("RenderCommandHelp() returned empty string")
	}
	if !strings.Contains(help, "scan") {
		t.Error("RenderCommandHelp() does not contain command name")
	}
}
