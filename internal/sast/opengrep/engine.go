package opengrep

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
	return "opengrep"
}

func (e *Engine) CheckInstalled() error {
	if _, err := exec.LookPath("opengrep"); err == nil {
		return nil
	}

	home, _ := os.UserHomeDir()
	localBin := filepath.Join(home, ".vulngate", "bin")
	binName := "opengrep"
	if runtime.GOOS == "windows" {
		binName = "opengrep.exe"
	}

	if _, err := os.Stat(filepath.Join(localBin, binName)); err == nil {
		currentPath := os.Getenv("PATH")
		os.Setenv("PATH", localBin+string(os.PathListSeparator)+currentPath)
		return nil
	}

	return fmt.Errorf("opengrep is not installed or not found in PATH\n\n" +
		"Install OpenGrep:\n" +
		"  vg install\n" +
		"  pip install opengrep\n\n" +
		"Documentation: https://opengrep.dev")
}

func (e *Engine) BuildArgs(req sast.ScanRequest) []string {
	args := []string{"opengrep", "scan"}

	if req.RulesPath != "" && !req.NoDefaultRules {
		args = append(args, "-f", req.RulesPath)
	} else if req.RulesPath != "" && req.NoDefaultRules {
		args = append(args, "-f", req.RulesPath)
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

type opengrepResult struct {
	Results []opengrepFinding `json:"results"`
}

type opengrepFinding struct {
	CheckID string            `json:"check_id"`
	Extra   opengrepExtra     `json:"extra"`
	Path    string            `json:"path"`
	Start   opengrepPosition  `json:"start"`
}

type opengrepExtra struct {
	Message  string           `json:"message"`
	Severity string           `json:"severity"`
	Metadata opengrepMetadata `json:"metadata"`
}

type opengrepPosition struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type opengrepMetadata struct {
	Category string `json:"category"`
	CWE      []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"cwe"`
}

func (e *Engine) ParseOutput(data []byte) ([]sast.Finding, error) {
	var result opengrepResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse opengrep output: %w", err)
	}

	findings := make([]sast.Finding, 0, len(result.Results))
	for _, r := range result.Results {
		f := sast.Finding{
			RuleID:   r.CheckID,
			Message:  r.Extra.Message,
			Severity: sast.ParseSeverity(strings.ToUpper(r.Extra.Severity)),
			File:     r.Path,
			Line:     r.Start.Line,
			Column:   r.Start.Col,
			Category: r.Extra.Metadata.Category,
		}
		if len(r.Extra.Metadata.CWE) > 0 {
			f.CWE = r.Extra.Metadata.CWE[0].ID
		}
		findings = append(findings, f)
	}

	return findings, nil
}
