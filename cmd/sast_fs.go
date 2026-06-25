package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/log"
	"github.com/leonardo-matheus/vulnscan/internal/sast"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var sastCfg struct {
	Engine         string
	RulesPath      string
	Format         string
	OutputPath     string
	FailOn         string
	Timeout        string
	Debug          bool
	NoDefaultRules bool
}

var sastFsCmd = &cobra.Command{
	Use:   "fs [path]",
	Short: "Run SAST scan on a filesystem directory",
	Long: `Run Static Application Security Testing on a local directory.

Detects insecure code patterns like SQL injection, XSS,
command injection, weak cryptography, and more.

Examples:
  vulngate sast fs .
  vulngate sast fs . --engine opengrep
  vulngate sast fs . --engine semgrep
  vulngate sast fs . --rules rules/sast
  vulngate sast fs . --format json --output report.json
  vulngate sast fs . --fail-on ERROR`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSAST(args[0])
	},
}

func init() {
	sastFsCmd.Flags().StringVar(&sastCfg.Engine, "engine", "opengrep", "SAST engine: opengrep, semgrep")
	sastFsCmd.Flags().StringVar(&sastCfg.RulesPath, "rules", "rules/sast", "path to rules directory or file")
	sastFsCmd.Flags().StringVar(&sastCfg.Format, "format", "table", "output format: table, json, sarif")
	sastFsCmd.Flags().StringVar(&sastCfg.OutputPath, "output", "", "output file path")
	sastFsCmd.Flags().StringVar(&sastCfg.FailOn, "fail-on", "ERROR", "minimum severity to fail: INFO, WARNING, ERROR")
	sastFsCmd.Flags().StringVar(&sastCfg.Timeout, "timeout", "10m", "scan timeout")
	sastFsCmd.Flags().BoolVar(&sastCfg.Debug, "debug", false, "enable debug output")
	sastFsCmd.Flags().BoolVar(&sastCfg.NoDefaultRules, "no-default-rules", false, "use only custom rules")
	sastCmd.AddCommand(sastFsCmd)
}

func runSAST(target string) error {
	engine, err := getEngine(sastCfg.Engine)
	if err != nil {
		return err
	}

	if err := engine.CheckInstalled(); err != nil {
		return err
	}

	timeout, err := time.ParseDuration(sastCfg.Timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}

	failOn := sast.ParseSeverity(sastCfg.FailOn)

	rulesPath := sastCfg.RulesPath
	if rulesPath != "" {
		if absPath, err := filepath.Abs(rulesPath); err == nil {
			rulesPath = absPath
		}
	}

	req := sast.ScanRequest{
		TargetPath:     target,
		Engine:         sastCfg.Engine,
		RulesPath:      rulesPath,
		Format:         sastCfg.Format,
		OutputPath:     sastCfg.OutputPath,
		FailOn:         failOn,
		Timeout:        timeout,
		Debug:          sastCfg.Debug,
		NoDefaultRules: sastCfg.NoDefaultRules,
	}

	if sastCfg.Debug {
		log.SetDebug(true)
	}

	fmt.Print(ui.RenderScanStart(target, "sast"))

	runner := sast.NewRunner(sastCfg.Debug)
	result, err := runner.Run(context.Background(), engine, req)
	if err != nil {
		return err
	}

	exitCode := sast.EvaluatePolicy(result, failOn)

	printSASTSummary(req, result, failOn, exitCode)

	if exitCode > 0 {
		os.Exit(exitCode)
	}

	return nil
}

func printSASTSummary(req sast.ScanRequest, result *sast.ScanResult, failOn sast.Severity, exitCode int) {
	infoCount := 0
	warnCount := 0
	errCount := 0

	for _, f := range result.Findings {
		switch f.Severity {
		case sast.SevInfo:
			infoCount++
		case sast.SevWarning:
			warnCount++
		case sast.SevError:
			errCount++
		}
	}

	total := len(result.Findings)

	fmt.Print("\n")

	if exitCode > 0 {
		fmt.Print(ui.ErrorBig.Render("  ✘ SAST issues detected"))
	} else if total > 0 {
		fmt.Print(ui.WarningBig.Render("  ⚠ SAST issues found (below threshold)"))
	} else {
		fmt.Print(ui.SuccessBig.Render("  ✔ No SAST issues found"))
	}

	fmt.Print("\n\n")

	boxLines := []string{}
	boxLines = append(boxLines, ui.SummaryHeader.Render("  SAST Summary"))
	boxLines = append(boxLines, "")
	boxLines = append(boxLines, fmt.Sprintf("  %s %s", ui.SummaryLabel.Render("Engine:"), ui.SummaryValue.Render(result.Engine)))
	boxLines = append(boxLines, fmt.Sprintf("  %s %s", ui.SummaryLabel.Render("Target:"), ui.SummaryValue.Render(truncatePath(req.TargetPath, 50))))
	boxLines = append(boxLines, "")

	if total > 0 {
		boxLines = append(boxLines, fmt.Sprintf("  %s %s", ui.SummaryLabel.Render("Total findings:"), ui.SummaryValue.Render(fmt.Sprintf("%d", total))))
		boxLines = append(boxLines, "")

		if errCount > 0 {
			boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityCriticalBadge.Render(fmt.Sprintf(" ERROR: %d ", errCount))))
		}
		if warnCount > 0 {
			boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityMediumBadge.Render(fmt.Sprintf(" WARNING: %d ", warnCount))))
		}
		if infoCount > 0 {
			boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityInfoBadge.Render(fmt.Sprintf(" INFO: %d ", infoCount))))
		}
		boxLines = append(boxLines, "")
		boxLines = append(boxLines, fmt.Sprintf("  %s %s", ui.SummaryLabel.Render("Fail-on policy:"), ui.SummaryValue.Render(failOn.String())))

		if exitCode > 0 {
			boxLines = append(boxLines, fmt.Sprintf("  %s %s", ui.SummaryLabel.Render("Blocked findings:"), ui.SeverityCriticalBadge.Render(fmt.Sprintf(" %d ", countBlocked(result.Findings, failOn)))))
		}
	} else {
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SummaryLabel.Render("Status:")))
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SuccessBig.Render("No issues detected")))
	}

	boxLines = append(boxLines, "")

	content := joinLines(boxLines)
	fmt.Print(ui.SummaryBox.Render(content))
	fmt.Print("\n")
}

func countBlocked(findings []sast.Finding, failOn sast.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity.GreaterOrEqual(failOn) {
			count++
		}
	}
	return count
}

func truncatePath(path string, max int) string {
	if len(path) <= max {
		return path
	}
	return path[:max-3] + "..."
}

func joinLines(lines []string) string {
	result := ""
	for _, l := range lines {
		result += l + "\n"
	}
	return result
}
