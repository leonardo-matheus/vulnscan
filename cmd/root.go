package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/config"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var (
	cfg          = config.DefaultScanOptions()
	flagSeverity string
	flagScanners string
)

var rootCmd = &cobra.Command{
	Use:   "vulngate",
	Short: "VulnGate — Vulnerability Scanner powered by Trivy",
	Long: `
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗  █████╗ ████████╗███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║██║  ███╗███████║   ██║   █████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║   ██║██╔══██║   ██║   ██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╔╝██║  ██║   ██║   ███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

  VulnGate — Vulnerability Scanner powered by Trivy
  Scan Java, Node.js, React, Vue.js projects for vulnerabilities`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		cfg.Severity = nil
		if flagSeverity != "" {
			parts := strings.Split(flagSeverity, ",")
			for _, p := range parts {
				s := config.Severity(strings.TrimSpace(strings.ToUpper(p)))
				if s.IsValid() {
					cfg.Severity = append(cfg.Severity, s)
				}
			}
		}
		if len(cfg.Severity) == 0 {
			cfg.Severity = []config.Severity{config.SeverityHigh, config.SeverityCritical}
		}

		cfg.Scanners = nil
		if flagScanners != "" {
			parts := strings.Split(flagScanners, ",")
			for _, p := range parts {
				s := config.Scanner(strings.TrimSpace(strings.ToLower(p)))
				if s.IsValid() {
					cfg.Scanners = append(cfg.Scanners, s)
				}
			}
		}
		if len(cfg.Scanners) == 0 {
			cfg.Scanners = []config.Scanner{config.ScannerVuln, config.ScannerSecret, config.ScannerMisconfig}
		}

		cfg.Format = config.Format(strings.ToLower(string(cfg.Format)))

		if cfg.Debug {
			fmt.Fprintf(os.Stderr, "%s\n",
				ui.StyleMuted.Render(fmt.Sprintf("[DEBUG] severity=%s scanners=%s format=%s timeout=%s",
					config.SeverityString(cfg.Severity), config.ScannerString(cfg.Scanners),
					cfg.Format, cfg.Timeout)))
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagSeverity, "severity", "HIGH,CRITICAL", "severity levels to report")
	rootCmd.PersistentFlags().StringVar((*string)(&cfg.Format), "format", "table", "output format: table, json, sarif")
	rootCmd.PersistentFlags().StringVar(&cfg.Output, "output", "", "output file path")
	rootCmd.PersistentFlags().IntVar(&cfg.ExitCode, "exit-code", 1, "exit code when vulnerabilities are found")
	rootCmd.PersistentFlags().BoolVar(&cfg.IgnoreUnfixed, "ignore-unfixed", false, "ignore vulnerabilities without a fix")
	rootCmd.PersistentFlags().BoolVar(&cfg.IncludeDevDeps, "include-dev-deps", false, "include dev dependencies (Node.js/React/Vue)")
	rootCmd.PersistentFlags().StringVar(&flagScanners, "scanners", "vuln,secret,misconfig", "scanner types to use")
	rootCmd.PersistentFlags().StringVar(&cfg.Timeout, "timeout", "10m", "scan timeout")
	rootCmd.PersistentFlags().BoolVar(&cfg.Debug, "debug", false, "enable debug output")

	rootCmd.SetHelpTemplate(rootCmd.HelpTemplate())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, ui.RenderError(err.Error()))
		os.Exit(1)
	}
}

var helpStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#CCCCCC"))

func init() {
	cobra.AddTemplateFunc("logo", func() string {
		return ui.RenderLogo()
	})

	cobra.AddTemplateFunc("divider", func() string {
		return ui.RenderDivider()
	})

	cobra.AddTemplateFunc("muted", func(s string) string {
		return ui.RenderMuted(s)
	})

	cobra.AddTemplateFunc("highlight", func(s string) string {
		return ui.RenderHighlight(s)
	})
}
