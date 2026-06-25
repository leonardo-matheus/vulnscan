package cmd

import (
	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var sastCmd = &cobra.Command{
	Use:   "sast",
	Short: "Static Application Security Testing (SAST)",
	Long: ui.RenderCommandHelp("sast",
		"Run SAST analysis using OpenGrep or Semgrep to detect insecure code patterns.",
		`  vulngate sast fs .                         Scan current directory
  vulngate sast fs . --engine opengrep       Use OpenGrep engine
  vulngate sast fs . --engine semgrep        Use Semgrep engine
  vulngate sast fs . --rules rules/sast      Use custom rules
  vulngate sast fs . --fail-on ERROR         Fail on ERROR severity`),
}

func init() {
	rootCmd.AddCommand(sastCmd)
}
