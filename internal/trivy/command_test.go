package trivy

import (
	"testing"

	"github.com/leonardo-matheus/vulnscan/internal/config"
)

func TestBuildFSArgs_DefaultOptions(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "/path/to/project"

	args := BuildFSArgs(opts)

	expected := []string{
		"fs",
		"--scanners", "vuln,secret,misconfig",
		"--severity", "HIGH,CRITICAL",
		"--exit-code", "1",
		"--format", "table",
		"--timeout", "10m",
		"/path/to/project",
	}

	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}

	for i, arg := range args {
		if arg != expected[i] {
			t.Errorf("arg[%d]: expected %q, got %q", i, expected[i], arg)
		}
	}
}

func TestBuildFSArgs_WithOutput(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "."
	opts.Output = "results.sarif"
	opts.Format = config.FormatSARIF

	args := BuildFSArgs(opts)

	found := false
	for i, arg := range args {
		if arg == "--output" && i+1 < len(args) && args[i+1] == "results.sarif" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected --output results.sarif in args")
	}

	foundFormat := false
	for i, arg := range args {
		if arg == "--format" && i+1 < len(args) && args[i+1] == "sarif" {
			foundFormat = true
			break
		}
	}

	if !foundFormat {
		t.Error("expected --format sarif in args")
	}
}

func TestBuildFSArgs_WithIgnoreUnfixed(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "."
	opts.IgnoreUnfixed = true

	args := BuildFSArgs(opts)

	found := false
	for _, arg := range args {
		if arg == "--ignore-unfixed" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected --ignore-unfixed in args")
	}
}

func TestBuildFSArgs_WithIncludeDevDeps(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "."
	opts.IncludeDevDeps = true

	args := BuildFSArgs(opts)

	found := false
	for _, arg := range args {
		if arg == "--include-dev-deps" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected --include-dev-deps in args")
	}
}

func TestBuildFSArgs_WithDebug(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "."
	opts.Debug = true

	args := BuildFSArgs(opts)

	found := false
	for _, arg := range args {
		if arg == "--debug" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected --debug in args")
	}
}

func TestBuildFSArgs_CustomSeverity(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "."
	opts.Severity = []config.Severity{config.SeverityLow, config.SeverityMedium, config.SeverityHigh, config.SeverityCritical}

	args := BuildFSArgs(opts)

	found := false
	for i, arg := range args {
		if arg == "--severity" && i+1 < len(args) && args[i+1] == "LOW,MEDIUM,HIGH,CRITICAL" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected --severity LOW,MEDIUM,HIGH,CRITICAL in args")
	}
}

func TestBuildFSArgs_CustomScanners(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "."
	opts.Scanners = []config.Scanner{config.ScannerVuln}

	args := BuildFSArgs(opts)

	found := false
	for i, arg := range args {
		if arg == "--scanners" && i+1 < len(args) && args[i+1] == "vuln" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected --scanners vuln in args")
	}
}

func TestBuildFSArgs_CustomTimeout(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "."
	opts.Timeout = "30m"

	args := BuildFSArgs(opts)

	found := false
	for i, arg := range args {
		if arg == "--timeout" && i+1 < len(args) && args[i+1] == "30m" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected --timeout 30m in args")
	}
}

func TestBuildFSArgs_JavaProject(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Target = "/workspace/java-project"
	opts.Scanners = []config.Scanner{config.ScannerVuln}
	opts.Severity = []config.Severity{config.SeverityCritical}

	args := BuildFSArgs(opts)

	if args[0] != "fs" {
		t.Errorf("expected first arg to be 'fs', got %q", args[0])
	}

	lastArg := args[len(args)-1]
	if lastArg != "/workspace/java-project" {
		t.Errorf("expected last arg to be target path, got %q", lastArg)
	}
}
