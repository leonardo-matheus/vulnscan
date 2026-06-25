package cmd

import (
	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan targets for vulnerabilities",
	Long: ui.RenderCommandHelp("scan",
		"Scan filesystem paths, Git repositories, or other targets using Trivy.",
		`  vulngate scan fs .                    Scan current directory
  vulngate scan fs /path/to/project     Scan a specific path
  vulngate scan repo https://github.com/org/repo  Scan a Git repository`),
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
