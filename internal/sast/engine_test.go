package sast

import (
	"testing"
	"time"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SevInfo, "INFO"},
		{SevWarning, "WARNING"},
		{SevError, "ERROR"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.expected {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.severity, got, tt.expected)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"INFO", SevInfo},
		{"WARNING", SevWarning},
		{"ERROR", SevError},
		{"UNKNOWN", SevError},
	}

	for _, tt := range tests {
		if got := ParseSeverity(tt.input); got != tt.expected {
			t.Errorf("ParseSeverity(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestSeverity_GreaterOrEqual(t *testing.T) {
	tests := []struct {
		a, b     Severity
		expected bool
	}{
		{SevError, SevWarning, true},
		{SevWarning, SevError, false},
		{SevError, SevError, true},
		{SevInfo, SevInfo, true},
		{SevInfo, SevWarning, false},
	}

	for _, tt := range tests {
		if got := tt.a.GreaterOrEqual(tt.b); got != tt.expected {
			t.Errorf("%v.GreaterOrEqual(%v) = %v, want %v", tt.a, tt.b, got, tt.expected)
		}
	}
}

func TestEvaluatePolicy(t *testing.T) {
	result := &ScanResult{
		Engine: "opengrep",
		Findings: []Finding{
			{RuleID: "r1", Severity: SevError},
			{RuleID: "r2", Severity: SevWarning},
			{RuleID: "r3", Severity: SevInfo},
		},
	}

	if got := EvaluatePolicy(result, SevError); got != 1 {
		t.Errorf("EvaluatePolicy(error) = %d, want 1", got)
	}

	if got := EvaluatePolicy(result, SevWarning); got != 1 {
		t.Errorf("EvaluatePolicy(warning) = %d, want 1", got)
	}

	if got := EvaluatePolicy(result, SevInfo); got != 1 {
		t.Errorf("EvaluatePolicy(info) = %d, want 1", got)
	}

	resultNoFindings := &ScanResult{
		Engine:   "opengrep",
		Findings: []Finding{},
	}

	if got := EvaluatePolicy(resultNoFindings, SevError); got != 0 {
		t.Errorf("EvaluatePolicy(no findings) = %d, want 0", got)
	}
}

func TestScanRequest_Defaults(t *testing.T) {
	req := ScanRequest{
		TargetPath: ".",
		Engine:     "opengrep",
		Format:     "table",
		FailOn:     SevError,
		Timeout:    10 * time.Minute,
	}

	if req.TargetPath != "." {
		t.Errorf("TargetPath = %q, want '.'", req.TargetPath)
	}

	if req.Engine != "opengrep" {
		t.Errorf("Engine = %q, want 'opengrep'", req.Engine)
	}

	if req.FailOn != SevError {
		t.Errorf("FailOn = %v, want SevError", req.FailOn)
	}
}

func TestFinding_Fields(t *testing.T) {
	f := Finding{
		RuleID:   "java-sql-injection",
		Message:  "SQL Injection detected",
		Severity: SevError,
		File:     "src/main.java",
		Line:     42,
		Column:   10,
		Category: "security",
		CWE:      "CWE-89",
	}

	if f.RuleID != "java-sql-injection" {
		t.Errorf("RuleID = %q", f.RuleID)
	}

	if f.Severity != SevError {
		t.Errorf("Severity = %v", f.Severity)
	}

	if f.Line != 42 {
		t.Errorf("Line = %d", f.Line)
	}
}
