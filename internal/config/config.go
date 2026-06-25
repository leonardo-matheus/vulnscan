package config

import (
	"fmt"
	"strings"
)

var (
	Version = "0.1.0"
	Commit  = "none"
	Date    = "unknown"
)

type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

type Scanner string

const (
	ScannerVuln       Scanner = "vuln"
	ScannerSecret     Scanner = "secret"
	ScannerMisconfig  Scanner = "misconfig"
)

type ScanOptions struct {
	Target         string
	Format         Format
	Severity       []Severity
	Output         string
	ExitCode       int
	IgnoreUnfixed  bool
	IncludeDevDeps bool
	Scanners       []Scanner
	Timeout        string
	Debug          bool
	EnableSAST     bool
}

func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Format:   FormatTable,
		Severity: []Severity{SeverityHigh, SeverityCritical},
		ExitCode: 1,
		Scanners: []Scanner{ScannerVuln, ScannerSecret, ScannerMisconfig},
		Timeout:  "10m",
	}
}

func (o ScanOptions) Validate() error {
	if o.Target == "" {
		return fmt.Errorf("target is required")
	}

	if !o.Format.IsValid() {
		return fmt.Errorf("unsupported format %q; supported: table, json, sarif", o.Format)
	}

	for _, s := range o.Severity {
		if !s.IsValid() {
			return fmt.Errorf("unsupported severity %q; supported: LOW, MEDIUM, HIGH, CRITICAL", s)
		}
	}

	if len(o.Scanners) == 0 {
		return fmt.Errorf("at least one scanner is required")
	}

	for _, sc := range o.Scanners {
		if !sc.IsValid() {
			return fmt.Errorf("unsupported scanner %q; supported: vuln, secret, misconfig", sc)
		}
	}

	return nil
}

func (f Format) IsValid() bool {
	switch f {
	case FormatTable, FormatJSON, FormatSARIF:
		return true
	}
	return false
}

func (s Severity) IsValid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func (s Scanner) IsValid() bool {
	switch s {
	case ScannerVuln, ScannerSecret, ScannerMisconfig:
		return true
	}
	return false
}

func SeverityString(severities []Severity) string {
	parts := make([]string, len(severities))
	for i, s := range severities {
		parts[i] = string(s)
	}
	return strings.Join(parts, ",")
}

func ScannerString(scanners []Scanner) string {
	parts := make([]string, len(scanners))
	for i, s := range scanners {
		parts[i] = string(s)
	}
	return strings.Join(parts, ",")
}
