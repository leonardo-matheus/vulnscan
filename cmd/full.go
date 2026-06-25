package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/config"
	"github.com/leonardo-matheus/vulnscan/internal/log"
	"github.com/leonardo-matheus/vulnscan/internal/output"
	"github.com/leonardo-matheus/vulnscan/internal/sast"
	"github.com/leonardo-matheus/vulnscan/internal/sast/opengrep"
	"github.com/leonardo-matheus/vulnscan/internal/sast/semgrep"
	"github.com/leonardo-matheus/vulnscan/internal/trivy"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var fullCfg struct {
	Target         string
	Engine         string
	RulesPath      string
	FailOn         string
	Timeout        string
	Debug          bool
	NoDefaultRules bool
}

var fullCmd = &cobra.Command{
	Use:   "full [path]",
	Short: "Run Trivy + SAST scan (full security analysis)",
	Long: `Run a complete security scan combining Trivy (dependencies, secrets, misconfigs)
and SAST (static code analysis) on a directory.

Examples:
  vg full                         Scan current directory
  vg full .                       Scan current directory
  vg full ./my-project            Scan specific directory
  vg full fs ./my-project         Scan with explicit fs subcommand
  vg full --engine semgrep        Use Semgrep instead of OpenGrep
  vg full --fail-on WARNING       Fail on WARNING severity`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}
		return runFull(target)
	},
	Aliases: []string{"f"},
}

var fullFsCmd = &cobra.Command{
	Use:   "fs [path]",
	Short: "Run Trivy + SAST scan on filesystem",
	Long: `Run a complete security scan on a filesystem directory.
This is an explicit form of the full scan command.

Examples:
  vg full fs .                    Scan current directory
  vg full fs ./my-project         Scan specific directory`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runFull(args[0])
	},
}

func init() {
	fullCmd.Flags().StringVar(&fullCfg.Engine, "engine", "opengrep", "SAST engine: opengrep, semgrep")
	fullCmd.Flags().StringVar(&fullCfg.RulesPath, "rules", "rules/sast", "path to SAST rules")
	fullCmd.Flags().StringVar(&fullCfg.FailOn, "fail-on", "ERROR", "minimum severity to fail: INFO, WARNING, ERROR")
	fullCmd.Flags().StringVar(&fullCfg.Timeout, "timeout", "10m", "scan timeout")
	fullCmd.Flags().BoolVar(&fullCfg.Debug, "debug", false, "enable debug output")
	fullCmd.Flags().BoolVar(&fullCfg.NoDefaultRules, "no-default-rules", false, "use only custom rules")

	fullFsCmd.Flags().StringVar(&fullCfg.Engine, "engine", "opengrep", "SAST engine: opengrep, semgrep")
	fullFsCmd.Flags().StringVar(&fullCfg.RulesPath, "rules", "rules/sast", "path to SAST rules")
	fullFsCmd.Flags().StringVar(&fullCfg.FailOn, "fail-on", "ERROR", "minimum severity to fail: INFO, WARNING, ERROR")
	fullFsCmd.Flags().StringVar(&fullCfg.Timeout, "timeout", "10m", "scan timeout")
	fullFsCmd.Flags().BoolVar(&fullCfg.Debug, "debug", false, "enable debug output")
	fullFsCmd.Flags().BoolVar(&fullCfg.NoDefaultRules, "no-default-rules", false, "use only custom rules")

	fullCmd.AddCommand(fullFsCmd)
	rootCmd.AddCommand(fullCmd)
}

func runFull(target string) error {
	if fullCfg.Debug {
		log.SetDebug(true)
	}

	fmt.Print(ui.RenderScanStart(target, "full (trivy + sast)"))

	trivyExitCode := runTrivyPart(target)

	sastExitCode := runSASTPart(target)

	finalExitCode := 0
	if trivyExitCode > 0 || sastExitCode > 0 {
		finalExitCode = 1
	}

	printFullSummary(target, trivyExitCode, sastExitCode, finalExitCode)

	if finalExitCode > 0 {
		os.Exit(finalExitCode)
	}

	return nil
}

func runTrivyPart(target string) int {
	cfg.Target = target
	cfg.Format = config.FormatTable
	cfg.Scanners = []config.Scanner{config.ScannerVuln, config.ScannerSecret, config.ScannerMisconfig}
	cfg.Severity = []config.Severity{config.SeverityHigh, config.SeverityCritical}

	trivyArgs := trivy.BuildFSArgs(cfg)

	if !trivy.IsInstalled() {
		log.Warn("Trivy not installed, skipping dependency scan")
		return 0
	}

	runner := trivy.NewRunner(fullCfg.Debug)
	exitCode, err := runner.Run(trivyArgs)
	if err != nil {
		log.Warn("Trivy scan error: %v", err)
		return 0
	}

	return exitCode
}

func runSASTPart(target string) int {
	engine, err := getEngine(fullCfg.Engine)
	if err != nil {
		log.Warn("SAST engine error: %v", err)
		return 0
	}

	if err := engine.CheckInstalled(); err != nil {
		log.Warn("SAST engine not installed: %v", err)
		return 0
	}

	timeout, err := time.ParseDuration(fullCfg.Timeout)
	if err != nil {
		timeout = 10 * time.Minute
	}

	failOn := sast.ParseSeverity(fullCfg.FailOn)

	req := sast.ScanRequest{
		TargetPath:     target,
		Engine:         fullCfg.Engine,
		RulesPath:      fullCfg.RulesPath,
		Format:         "json",
		FailOn:         failOn,
		Timeout:        timeout,
		Debug:          fullCfg.Debug,
		NoDefaultRules: fullCfg.NoDefaultRules,
	}

	runner := sast.NewRunner(fullCfg.Debug)
	result, err := runner.Run(context.Background(), engine, req)
	if err != nil {
		log.Warn("SAST scan error: %v", err)
		return 0
	}

	return sast.EvaluatePolicy(result, failOn)
}

func getEngine(name string) (sast.Engine, error) {
	switch name {
	case "opengrep":
		return opengrep.New(), nil
	case "semgrep":
		return semgrep.New(), nil
	default:
		return nil, fmt.Errorf("unsupported engine %q", name)
	}
}

func printFullSummary(target string, trivyExit, sastExit, finalExit int) {
	fmt.Print("\n")

	if finalExit > 0 {
		fmt.Print(ui.ErrorBig.Render("  ✘ Security issues detected"))
	} else {
		fmt.Print(ui.SuccessBig.Render("  ✔ No security issues found"))
	}

	fmt.Print("\n\n")

	boxLines := []string{}
	boxLines = append(boxLines, ui.SummaryHeader.Render("  Full Scan Summary"))
	boxLines = append(boxLines, "")
	boxLines = append(boxLines, fmt.Sprintf("  %s %s", ui.SummaryLabel.Render("Target:"), ui.SummaryValue.Render(truncatePath(target, 50))))
	boxLines = append(boxLines, "")

	boxLines = append(boxLines, ui.SummaryHeader.Render("  Trivy (Dependencies)"))
	if trivyExit > 0 {
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityCriticalBadge.Render(" ISSUES FOUND ")))
	} else {
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityInfoBadge.Render(" CLEAN ")))
	}
	boxLines = append(boxLines, "")

	boxLines = append(boxLines, ui.SummaryHeader.Render("  SAST (Code Analysis)"))
	if sastExit > 0 {
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityCriticalBadge.Render(" ISSUES FOUND ")))
	} else {
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityInfoBadge.Render(" CLEAN ")))
	}
	boxLines = append(boxLines, "")

	if finalExit > 0 {
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityCriticalBadge.Render(" PIPELINE BLOCKED ")))
	} else {
		boxLines = append(boxLines, fmt.Sprintf("  %s", ui.SeverityInfoBadge.Render(" PIPELINE PASSED ")))
	}
	boxLines = append(boxLines, "")

	content := joinLines(boxLines)
	fmt.Print(ui.SummaryBox.Render(content))
	fmt.Print("\n")
}

func init() {
	_ = output.EnsureOutputDir
}
