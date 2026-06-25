package semgrep

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/leonardo-matheus/vulnscan/internal/sast"
)

type Engine struct{}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Name() string {
	return "semgrep"
}

func (e *Engine) CheckInstalled() error {
	if _, err := exec.LookPath("semgrep"); err == nil {
		return nil
	}

	home, _ := os.UserHomeDir()
	localBin := filepath.Join(home, ".vulngate", "bin")
	binName := "semgrep"
	if runtime.GOOS == "windows" {
		binName = "semgrep.exe"
	}

	if _, err := os.Stat(filepath.Join(localBin, binName)); err == nil {
		currentPath := os.Getenv("PATH")
		os.Setenv("PATH", localBin+string(os.PathListSeparator)+currentPath)
		return nil
	}

	return fmt.Errorf("semgrep is not installed or not found in PATH\n\n" +
		"Install Semgrep:\n" +
		"  pip install semgrep\n" +
		"  brew install semgrep (macOS)\n\n" +
		"Documentation: https://semgrep.dev")
}

func (e *Engine) BuildArgs(req sast.ScanRequest) []string {
	args := []string{"semgrep", "scan"}

	if req.RulesPath != "" {
		args = append(args, "--config", req.RulesPath)
	} else {
		args = append(args, "--config", "auto")
	}

	switch req.Format {
	case "json":
		args = append(args, "--json")
	case "sarif":
		args = append(args, "--sarif")
	default:
		args = append(args, "--json")
	}

	if req.OutputPath != "" {
		args = append(args, "--output", req.OutputPath)
	}

	args = append(args, ".")

	return args
}

type semgrepResult struct {
	Results []semgrepFinding `json:"results"`
}

type semgrepFinding struct {
	CheckID string            `json:"check_id"`
	Message  string           `json:"extra.message"`
	Severity string           `json:"extra.severity"`
	Path     string           `json:"path"`
	Start    semgrepPosition  `json:"start"`
	Metadata semgrepMetadata  `json:"extra.metadata"`
}

type semgrepPosition struct {
	Line   int `json:"line"`
	Column int `json:"col"`
}

type semgrepMetadata struct {
	Category string `json:"category"`
	CWE      []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"cwe"`
}

func (e *Engine) ParseOutput(data []byte) ([]sast.Finding, error) {
	var result semgrepResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	findings := make([]sast.Finding, 0, len(result.Results))
	for _, r := range result.Results {
		f := sast.Finding{
			RuleID:   r.CheckID,
			Message:  r.Message,
			Severity: sast.ParseSeverity(strings.ToUpper(r.Severity)),
			File:     r.Path,
			Line:     r.Start.Line,
			Column:   r.Start.Column,
			Category: r.Metadata.Category,
		}
		if len(r.Metadata.CWE) > 0 {
			f.CWE = r.Metadata.CWE[0].ID
		}
		findings = append(findings, f)
	}

	return findings, nil
}
