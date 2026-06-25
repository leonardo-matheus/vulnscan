package sast

import "time"

type Severity int

const (
	SevInfo Severity = iota
	SevWarning
	SevError
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevWarning:
		return "WARNING"
	case SevError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func ParseSeverity(s string) Severity {
	switch s {
	case "INFO":
		return SevInfo
	case "WARNING":
		return SevWarning
	case "ERROR":
		return SevError
	default:
		return SevError
	}
}

func (s Severity) Less(other Severity) bool {
	return s < other
}

func (s Severity) GreaterOrEqual(other Severity) bool {
	return s >= other
}

type ScanRequest struct {
	TargetPath     string
	Engine         string
	RulesPath      string
	Format         string
	OutputPath     string
	FailOn         Severity
	Timeout        time.Duration
	Debug          bool
	NoDefaultRules bool
}

type ScanResult struct {
	Engine     string
	Findings   []Finding
	RawOutput  []byte
	ExitCode   int
}

type Finding struct {
	RuleID   string
	Message  string
	Severity Severity
	File     string
	Line     int
	Column   int
	Category string
	CWE      string
}

type Engine interface {
	Name() string
	CheckInstalled() error
	BuildArgs(req ScanRequest) []string
	ParseOutput(data []byte) ([]Finding, error)
}
