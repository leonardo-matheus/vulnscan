package cmd

import (
	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var sastCmd = &cobra.Command{
	Use:   "sast [path]",
	Short: "Static Application Security Testing (SAST)",
	Long: ui.RenderCommandHelp("sast",
		"Run SAST analysis using OpenGrep or Semgrep to detect insecure code patterns.",
		`  vg sast                            Scan current directory
  vg sast .                           Scan current directory
  vg sast /path/to/project            Scan a specific path
  vg sast fs /path/to/project         Scan with explicit fs subcommand
  vg sast --engine opengrep           Use OpenGrep engine
  vg sast --engine semgrep            Use Semgrep engine
  vg sast --rules rules/sast          Use custom rules
  vg sast --fail-on ERROR             Fail on ERROR severity`),
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}
		return runSAST(target)
	},
}

func init() {
	sastCmd.Flags().StringVar(&sastCfg.Engine, "engine", "opengrep", "SAST engine: opengrep, semgrep")
	sastCmd.Flags().StringVar(&sastCfg.RulesPath, "rules", "rules/sast", "path to rules directory or file")
	sastCmd.Flags().StringVar(&sastCfg.Format, "format", "table", "output format: table, json, sarif")
	sastCmd.Flags().StringVar(&sastCfg.OutputPath, "output", "", "output file path")
	sastCmd.Flags().StringVar(&sastCfg.FailOn, "fail-on", "ERROR", "minimum severity to fail: INFO, WARNING, ERROR")
	sastCmd.Flags().StringVar(&sastCfg.Timeout, "timeout", "10m", "scan timeout")
	sastCmd.Flags().BoolVar(&sastCfg.Debug, "debug", false, "enable debug output")
	sastCmd.Flags().BoolVar(&sastCfg.NoDefaultRules, "no-default-rules", false, "use only custom rules")

	rootCmd.AddCommand(sastCmd)
}
