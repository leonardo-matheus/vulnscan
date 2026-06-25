package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/config"
	"github.com/leonardo-matheus/vulnscan/internal/git"
	"github.com/leonardo-matheus/vulnscan/internal/log"
	"github.com/leonardo-matheus/vulnscan/internal/output"
	"github.com/leonardo-matheus/vulnscan/internal/trivy"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var scanRepoCmd = &cobra.Command{
	Use:   "repo [git-url]",
	Short: "Scan a Git repository",
	Long: `Clone a Git repository temporarily and scan it for vulnerabilities,
secrets, and misconfigurations using Trivy.

Examples:
  vulngate scan repo https://github.com/org/repo
  vulngate scan repo git@github.com:org/repo.git
  vulngate scan repo https://github.com/org/repo --severity HIGH,CRITICAL
  vulngate scan repo https://github.com/org/repo --format sarif --output report.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := trivy.EnsureInstalled(); err != nil {
			return err
		}

		repoURL := args[0]
		if repoURL == "" {
			return fmt.Errorf("git repository URL is required")
		}

		if cfg.Debug {
			log.SetDebug(true)
		}

		fmt.Print(ui.RenderMuted(fmt.Sprintf("Cloning repository: %s\n", repoURL)))

		tmpDir, cleanup, err := git.CloneTemp(repoURL)
		if err != nil {
			return err
		}
		defer cleanup()

		fmt.Print(ui.RenderSuccess(fmt.Sprintf("Repository cloned to: %s\n", tmpDir)))

		cfg.Target = tmpDir

		if err := cfg.Validate(); err != nil {
			return err
		}

		if err := output.EnsureOutputDir(cfg.Output); err != nil {
			return err
		}

		trivyArgs := trivy.BuildFSArgs(cfg)

		log.Debug("scan options: format=%s severity=%s scanners=%s",
			cfg.Format, config.SeverityString(cfg.Severity), config.ScannerString(cfg.Scanners))

		if cfg.Format != config.FormatTable {
			return runPlainScan(trivyArgs)
		}

		return runPrettyScan(repoURL, "repository", trivyArgs)
	},
}

func init() {
	scanCmd.AddCommand(scanRepoCmd)
}

func formatRepoDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
