package config

import (
	"testing"
)

func TestValidate_ValidOptions(t *testing.T) {
	opts := DefaultScanOptions()
	opts.Target = "."

	if err := opts.Validate(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidate_EmptyTarget(t *testing.T) {
	opts := DefaultScanOptions()
	opts.Target = ""

	err := opts.Validate()
	if err == nil {
		t.Error("expected error for empty target")
	}
}

func TestValidate_InvalidFormat(t *testing.T) {
	opts := DefaultScanOptions()
	opts.Target = "."
	opts.Format = Format("xml")

	err := opts.Validate()
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	opts := DefaultScanOptions()
	opts.Target = "."
	opts.Severity = []Severity{"EXTREME"}

	err := opts.Validate()
	if err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestValidate_InvalidScanner(t *testing.T) {
	opts := DefaultScanOptions()
	opts.Target = "."
	opts.Scanners = []Scanner{"virus"}

	err := opts.Validate()
	if err == nil {
		t.Error("expected error for invalid scanner")
	}
}

func TestValidate_EmptyScanners(t *testing.T) {
	opts := DefaultScanOptions()
	opts.Target = "."
	opts.Scanners = []Scanner{}

	err := opts.Validate()
	if err == nil {
		t.Error("expected error for empty scanners")
	}
}

func TestFormat_IsValid(t *testing.T) {
	tests := []struct {
		format Format
		valid  bool
	}{
		{FormatTable, true},
		{FormatJSON, true},
		{FormatSARIF, true},
		{Format("xml"), false},
		{Format(""), false},
	}

	for _, tt := range tests {
		if got := tt.format.IsValid(); got != tt.valid {
			t.Errorf("Format(%q).IsValid() = %v, want %v", tt.format, got, tt.valid)
		}
	}
}

func TestSeverity_IsValid(t *testing.T) {
	tests := []struct {
		severity Severity
		valid    bool
	}{
		{SeverityLow, true},
		{SeverityMedium, true},
		{SeverityHigh, true},
		{SeverityCritical, true},
		{Severity("EXTREME"), false},
		{Severity(""), false},
	}

	for _, tt := range tests {
		if got := tt.severity.IsValid(); got != tt.valid {
			t.Errorf("Severity(%q).IsValid() = %v, want %v", tt.severity, got, tt.valid)
		}
	}
}

func TestScanner_IsValid(t *testing.T) {
	tests := []struct {
		scanner Scanner
		valid   bool
	}{
		{ScannerVuln, true},
		{ScannerSecret, true},
		{ScannerMisconfig, true},
		{Scanner("virus"), false},
		{Scanner(""), false},
	}

	for _, tt := range tests {
		if got := tt.scanner.IsValid(); got != tt.valid {
			t.Errorf("Scanner(%q).IsValid() = %v, want %v", tt.scanner, got, tt.valid)
		}
	}
}

func TestSeverityString(t *testing.T) {
	severities := []Severity{SeverityHigh, SeverityCritical}
	got := SeverityString(severities)
	want := "HIGH,CRITICAL"

	if got != want {
		t.Errorf("SeverityString() = %q, want %q", got, want)
	}
}

func TestScannerString(t *testing.T) {
	scanners := []Scanner{ScannerVuln, ScannerSecret, ScannerMisconfig}
	got := ScannerString(scanners)
	want := "vuln,secret,misconfig"

	if got != want {
		t.Errorf("ScannerString() = %q, want %q", got, want)
	}
}

func TestDefaultScanOptions(t *testing.T) {
	opts := DefaultScanOptions()

	if opts.Format != FormatTable {
		t.Errorf("default format = %q, want table", opts.Format)
	}

	if opts.ExitCode != 1 {
		t.Errorf("default exit code = %d, want 1", opts.ExitCode)
	}

	if opts.Timeout != "10m" {
		t.Errorf("default timeout = %q, want 10m", opts.Timeout)
	}

	if len(opts.Severity) != 2 {
		t.Errorf("default severity count = %d, want 2", len(opts.Severity))
	}

	if opts.Severity[0] != SeverityHigh || opts.Severity[1] != SeverityCritical {
		t.Errorf("default severity = %v, want [HIGH, CRITICAL]", opts.Severity)
	}

	if len(opts.Scanners) != 3 {
		t.Errorf("default scanners count = %d, want 3", len(opts.Scanners))
	}
}
