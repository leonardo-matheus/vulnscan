package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/config"
	"github.com/leonardo-matheus/vulnscan/internal/trivy"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Show the version of VulnGate and the installed Trivy version.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		trivyVersion := ""
		if trivy.IsInstalled() {
			ver, err := trivy.Version()
			if err == nil {
				trivyVersion = ver
			}
		}

		fmt.Print(ui.RenderVersion(config.Version, config.Commit, config.Date, trivyVersion))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
