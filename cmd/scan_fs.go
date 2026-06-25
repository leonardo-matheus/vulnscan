package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/config"
	"github.com/leonardo-matheus/vulnscan/internal/log"
	"github.com/leonardo-matheus/vulnscan/internal/output"
	"github.com/leonardo-matheus/vulnscan/internal/trivy"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var scanFsCmd = &cobra.Command{
	Use:   "fs [path]",
	Short: "Scan a filesystem directory",
	Long: `Scan a local directory for vulnerabilities, secrets, and
misconfigurations using Trivy.

Examples:
  vulngate scan fs .
  vulngate scan fs /path/to/project
  vulngate scan fs ./my-java-app --severity HIGH,CRITICAL
  vulngate scan fs ./my-node-app --include-dev-deps
  vulngate scan fs . --format sarif --output results.sarif
  vulngate scan fs . --enable-sast`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := trivy.EnsureInstalled(); err != nil {
			return err
		}

		cfg.Target = args[0]

		if err := cfg.Validate(); err != nil {
			return err
		}

		if err := output.EnsureOutputDir(cfg.Output); err != nil {
			return err
		}

		if cfg.Debug {
			log.SetDebug(true)
		}

		trivyArgs := trivy.BuildFSArgs(cfg)

		log.Debug("scan options: format=%s severity=%s scanners=%s",
			cfg.Format, config.SeverityString(cfg.Severity), config.ScannerString(cfg.Scanners))

		if cfg.Format != config.FormatTable {
			return runPlainScan(trivyArgs)
		}

		return runPrettyScan(cfg.Target, "filesystem", trivyArgs)
	},
}

func runPrettyScan(target, scanType string, args []string) error {
	reportPath := trivy.GenerateReportPath(target)
	sarifPath := trivy.GenerateSARIFPath(target)

	runner := trivy.NewRunner(false)

	start := time.Now()

	progress := ui.NewScanProgress(scanType, target)
	progress.Start()

	jsonArgs := trivy.BuildJSONArgs(args, reportPath)

	exitCode, err := runner.RunWithProgress(jsonArgs, func(phase string, num int) {
		progress.SetPhase(phase, num)
	})

	progress.Stop()

	if err != nil {
		return err
	}

	elapsed := time.Since(start)

	sarifRunner := trivy.NewRunner(false)
	sarifArgs := trivy.BuildSARIFArgs(args, sarifPath)
	sarifRunner.Run(sarifArgs)

	summary, parseErr := trivy.ParseReport(reportPath)
	if parseErr != nil {
		log.Debug("Could not parse JSON report: %v", parseErr)
		summary = &ui.ScanSummary{
			Target:   target,
			ScanType: scanType,
			ExitCode: exitCode,
		}
	}

	summary.Target = target
	summary.ScanType = scanType
	summary.ExitCode = exitCode
	summary.Duration = formatDuration(elapsed)
	summary.OutputPath = sarifPath
	summary.SARIFPath = reportPath

	fmt.Print(ui.RenderScanSummary(*summary))

	if exitCode > 0 {
		os.Exit(exitCode)
	}

	return nil
}

func runPlainScan(args []string) error {
	runner := trivy.NewRunner(cfg.Debug)

	start := time.Now()
	fmt.Fprintln(os.Stderr, ui.RenderMuted("Scanning..."))

	exitCode, err := runner.Run(args)
	if err != nil {
		return err
	}

	elapsed := time.Since(start)
	elapsedStr := formatDuration(elapsed)

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, ui.RenderMuted(fmt.Sprintf("Scan completed in %s", elapsedStr)))

	if exitCode > 0 {
		fmt.Fprintln(os.Stderr, ui.RenderError(fmt.Sprintf("Vulnerabilities found (exit code: %d)", exitCode)))
		os.Exit(exitCode)
	}

	return nil
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func init() {
	scanFsCmd.Flags().BoolVar(&cfg.EnableSAST, "enable-sast", false, "enable SAST analysis after Trivy scan")
	scanCmd.AddCommand(scanFsCmd)
}
