package semgrep

import (
	"testing"

	"github.com/leonardo-matheus/vulnscan/internal/sast"
)

func TestEngine_Name(t *testing.T) {
	e := New()
	if e.Name() != "semgrep" {
		t.Errorf("Name() = %q, want 'semgrep'", e.Name())
	}
}

func TestEngine_BuildArgs_Default(t *testing.T) {
	e := New()
	req := sast.ScanRequest{
		TargetPath: ".",
		RulesPath:  "rules/sast",
		Format:     "json",
	}

	args := e.BuildArgs(req)

	if args[0] != "semgrep" {
		t.Errorf("args[0] = %q, want 'semgrep'", args[0])
	}

	if args[1] != "scan" {
		t.Errorf("args[1] = %q, want 'scan'", args[1])
	}

	foundConfig := false
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) && args[i+1] == "rules/sast" {
			foundConfig = true
			break
		}
	}
	if !foundConfig {
		t.Error("expected --config rules/sast in args")
	}

	foundJson := false
	for _, arg := range args {
		if arg == "--json" {
			foundJson = true
			break
		}
	}
	if !foundJson {
		t.Error("expected --json in args")
	}
}

func TestEngine_BuildArgs_NoRules(t *testing.T) {
	e := New()
	req := sast.ScanRequest{
		TargetPath: ".",
		Format:     "json",
	}

	args := e.BuildArgs(req)

	foundAuto := false
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) && args[i+1] == "auto" {
			foundAuto = true
			break
		}
	}
	if !foundAuto {
		t.Error("expected --config auto when no rules specified")
	}
}

func TestEngine_BuildArgs_SARIF(t *testing.T) {
	e := New()
	req := sast.ScanRequest{
		TargetPath: ".",
		Format:     "sarif",
		OutputPath: "report.sarif",
	}

	args := e.BuildArgs(req)

	foundSarif := false
	for _, arg := range args {
		if arg == "--sarif" {
			foundSarif = true
			break
		}
	}
	if !foundSarif {
		t.Error("expected --sarif in args")
	}

	foundOutput := false
	for i, arg := range args {
		if arg == "--output" && i+1 < len(args) && args[i+1] == "report.sarif" {
			foundOutput = true
			break
		}
	}
	if !foundOutput {
		t.Error("expected --output report.sarif in args")
	}
}

func TestEngine_ParseOutput_Empty(t *testing.T) {
	e := New()
	data := []byte(`{"results": []}`)

	findings, err := e.ParseOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestEngine_ParseOutput_WithFindings(t *testing.T) {
	e := New()
	data := []byte(`{
		"results": [
			{
				"check_id": "react-dangerously-set-inner-html",
				"extra": {
					"message": "XSS risk detected",
					"severity": "ERROR",
					"metadata": {
						"category": "security",
						"cwe": [{"id": "CWE-79", "name": "XSS"}]
					}
				},
				"path": "src/App.jsx",
				"start": {"line": 15, "col": 5}
			}
		]
	}`)

	findings, err := e.ParseOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "react-dangerously-set-inner-html" {
		t.Errorf("RuleID = %q", f.RuleID)
	}

	if f.Severity != sast.SevError {
		t.Errorf("Severity = %v, want ERROR", f.Severity)
	}

	if f.File != "src/App.jsx" {
		t.Errorf("File = %q", f.File)
	}

	if f.Line != 15 {
		t.Errorf("Line = %d", f.Line)
	}
}

func TestEngine_ParseOutput_InvalidJSON(t *testing.T) {
	e := New()
	data := []byte(`not json`)

	_, err := e.ParseOutput(data)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
