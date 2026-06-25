package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/config"
	"github.com/leonardo-matheus/vulnscan/internal/log"
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

	fullCmd.AddCommand(fullFsCmd)
	rootCmd.AddCommand(fullCmd)
}

func runFull(target string) error {
	if fullCfg.Debug {
		log.SetDebug(true)
	}

	clearScreen()
	fmt.Print(ui.RenderLogo())
	fmt.Print("\n")

	absTarget, _ := filepath.Abs(target)
	fmt.Printf("  %s %s\n\n", ui.SummaryLabel.Render("Target:"), absTarget)

	start := time.Now()

	spinner := ui.NewScanProgress("full", target)
	spinner.Start()

	trivyRes := runTrivyPart(target, spinner)

	sastRes := runSASTPart(target, spinner)

	spinner.Stop()

	elapsed := time.Since(start)

	finalExitCode := 0
	if trivyRes.exitCode > 0 || sastRes.exitCode > 0 {
		finalExitCode = 1
	}

	printFullCleanSummary(absTarget, trivyRes, sastRes, elapsed, finalExitCode)

	if finalExitCode > 0 {
		os.Exit(finalExitCode)
	}

	return nil
}

type trivyResult struct {
	exitCode       int
	vulnCount      int
	secretCount    int
	misconfigCount int
	critical       int
	high           int
}

type sastResult struct {
	exitCode   int
	total      int
	errorCount int
	warnCount  int
	infoCount  int
}

func runTrivyPart(target string, spinner *ui.ScanProgress) trivyResult {
	result := trivyResult{}

	if !trivy.IsInstalled() {
		spinner.SetPhase("Trivy: not installed", 1)
		return result
	}

	spinner.SetPhase("Trivy: scanning dependencies...", 1)

	cfg.Target = target
	cfg.Format = "json"
	cfg.Scanners = []config.Scanner{config.ScannerVuln, config.ScannerSecret, config.ScannerMisconfig}
	cfg.Severity = []config.Severity{config.SeverityLow, config.SeverityMedium, config.SeverityHigh, config.SeverityCritical}

	reportPath := trivy.GenerateReportPath(target)
	trivyArgs := trivy.BuildFSArgs(cfg)
	trivyArgs = trivy.BuildJSONArgs(trivyArgs, reportPath)

	runner := trivy.NewRunner(fullCfg.Debug)
	exitCode, err := runner.Run(trivyArgs)

	result.exitCode = exitCode

	if err != nil {
		log.Debug("Trivy error: %v", err)
		return result
	}

	summary, parseErr := trivy.ParseReport(reportPath)
	if parseErr != nil {
		log.Debug("Parse error: %v", parseErr)
		return result
	}

	result.vulnCount = summary.VulnTotal
	result.secretCount = summary.SecretTotal
	result.misconfigCount = summary.MisconfigTotal
	result.critical = summary.VulnCritical + summary.MisconfigCritical
	result.high = summary.VulnHigh + summary.MisconfigHigh

	return result
}

func runSASTPart(target string, spinner *ui.ScanProgress) sastResult {
	result := sastResult{}

	engine, err := getEngine(fullCfg.Engine)
	if err != nil {
		spinner.SetPhase("SAST: engine error", 2)
		return result
	}

	if err := engine.CheckInstalled(); err != nil {
		spinner.SetPhase("SAST: not installed", 2)
		return result
	}

	spinner.SetPhase("SAST: analyzing code...", 2)

	timeout, err := time.ParseDuration(fullCfg.Timeout)
	if err != nil {
		timeout = 10 * time.Minute
	}

	failOn := sast.ParseSeverity(fullCfg.FailOn)

	rulesPath := fullCfg.RulesPath
	if rulesPath != "" {
		if absPath, err := filepath.Abs(rulesPath); err == nil {
			rulesPath = absPath
		}
	}

	req := sast.ScanRequest{
		TargetPath:     target,
		Engine:         fullCfg.Engine,
		RulesPath:      rulesPath,
		Format:         "json",
		FailOn:         failOn,
		Timeout:        timeout,
		Debug:          fullCfg.Debug,
		NoDefaultRules: fullCfg.NoDefaultRules,
	}

	runner := sast.NewRunner(fullCfg.Debug)
	sastRes, err := runner.Run(context.Background(), engine, req)
	if err != nil {
		log.Debug("SAST error: %v", err)
		return result
	}

	result.exitCode = sast.EvaluatePolicy(sastRes, failOn)
	result.total = len(sastRes.Findings)

	for _, f := range sastRes.Findings {
		switch f.Severity {
		case sast.SevError:
			result.errorCount++
		case sast.SevWarning:
			result.warnCount++
		case sast.SevInfo:
			result.infoCount++
		}
	}

	return result
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

func printFullCleanSummary(target string, trivyRes trivyResult, sastRes sastResult, elapsed time.Duration, finalExit int) {
	fmt.Print("\n")

	if finalExit > 0 {
		fmt.Print(ui.ErrorBig.Render("  ✘ Security issues found"))
	} else {
		fmt.Print(ui.SuccessBig.Render("  ✔ No security issues found"))
	}

	fmt.Print("\n\n")

	trivyLine := "CLEAN"
	if trivyRes.vulnCount+trivyRes.secretCount+trivyRes.misconfigCount > 0 {
		trivyLine = fmt.Sprintf("%d findings", trivyRes.vulnCount+trivyRes.secretCount+trivyRes.misconfigCount)
	}

	sastLine := "CLEAN"
	if sastRes.total > 0 {
		sastLine = fmt.Sprintf("%d findings", sastRes.total)
	}

	severityLine := ""
	if trivyRes.critical > 0 || trivyRes.high > 0 {
		parts := []string{}
		if trivyRes.critical > 0 {
			parts = append(parts, fmt.Sprintf("%d CRITICAL", trivyRes.critical))
		}
		if trivyRes.high > 0 {
			parts = append(parts, fmt.Sprintf("%d HIGH", trivyRes.high))
		}
		severityLine = "            " + ui.SeverityCriticalBadge.Render(strings.Join(parts, " ")) + "\n"
	}

	sastBadgeLine := ""
	if sastRes.total > 0 {
		parts := []string{}
		if sastRes.errorCount > 0 {
			parts = append(parts, fmt.Sprintf("%d ERROR", sastRes.errorCount))
		}
		if sastRes.warnCount > 0 {
			parts = append(parts, fmt.Sprintf("%d WARNING", sastRes.warnCount))
		}
		if len(parts) > 0 {
			sastBadgeLine = "            " + ui.SeverityCriticalBadge.Render(strings.Join(parts, " ")) + "\n"
		}
	}

	pipeline := ui.SeverityInfoBadge.Render(" PIPELINE PASSED ")
	if finalExit > 0 {
		pipeline = ui.SeverityCriticalBadge.Render(" PIPELINE BLOCKED ")
	}

	summary := ui.SummaryHeader.Render("  Scan Results") + "\n\n" +
		fmt.Sprintf("  %-20s %s\n", "Target:", truncatePath(target, 38)) +
		fmt.Sprintf("  %-20s %s\n", "Duration:", formatDuration(elapsed)) + "\n" +
		ui.SummaryHeader.Render("  Trivy") + "\n" +
		fmt.Sprintf("  %-20s %s\n", "Dependencies:", trivyLine) +
		fmt.Sprintf("  %-20s %s\n", "Secrets:", secretLine(trivyRes.secretCount)) +
		fmt.Sprintf("  %-20s %s\n", "Misconfigs:", misconfigLine(trivyRes.misconfigCount)) +
		severityLine + "\n" +
		ui.SummaryHeader.Render("  SAST") + "\n" +
		fmt.Sprintf("  %-20s %s\n", "Engine:", fullCfg.Engine) +
		fmt.Sprintf("  %-20s %s\n", "Findings:", sastLine) +
		sastBadgeLine + "\n" +
		"  " + pipeline + "\n"

	fmt.Print(ui.SummaryBox.Render(summary))
	fmt.Print("\n")
}

func secretLine(count int) string {
	if count == 0 {
		return "CLEAN"
	}
	return fmt.Sprintf("%d found", count)
}

func misconfigLine(count int) string {
	if count == 0 {
		return "CLEAN"
	}
	return fmt.Sprintf("%d found", count)
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}
