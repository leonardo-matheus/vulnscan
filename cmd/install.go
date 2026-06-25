package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/leonardo-matheus/vulnscan/internal/config"
	"github.com/leonardo-matheus/vulnscan/internal/install"
	"github.com/leonardo-matheus/vulnscan/internal/trivy"
	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install VulnGate and Trivy",
	Long: `Install VulnGate and Trivy to ~/.vulngate/bin/ and add to PATH.

This command will:
  - Copy VulnGate binary to ~/.vulngate/bin/
  - Download the latest Trivy release for your platform
  - Extract Trivy to ~/.vulngate/bin/
  - Add the directory to your PATH (user-level)

Run with --check to verify if both are already installed.
Run with --force to reinstall even if already installed.`,
	Aliases: []string{"setup"},
	RunE: func(cmd *cobra.Command, args []string) error {
		checkOnly, _ := cmd.Flags().GetBool("check")
		force, _ := cmd.Flags().GetBool("force")

		if checkOnly {
			return runCheck()
		}

		return runInstall(force)
	},
}

func init() {
	installCmd.Flags().BoolP("check", "c", false, "Only check if VulnGate and Trivy are installed")
	installCmd.Flags().BoolP("force", "f", false, "Force reinstall even if already installed")
	rootCmd.AddCommand(installCmd)
}

func runCheck() error {
	vulngateInstalled := isVulngateInInstallDir()
	trivyInstalled := trivy.IsInstalled()

	if vulngateInstalled && trivyInstalled {
		fmt.Print(ui.RenderSuccess("VulnGate and Trivy are installed"))
		fmt.Println()

		ver, _ := trivy.Version()
		fmt.Println(ui.RenderMuted(ver))

		home, _ := os.UserHomeDir()
		installDir := filepath.Join(home, ".vulngate", "bin")
		fmt.Println(ui.RenderMuted(fmt.Sprintf("Location: %s", installDir)))
		return nil
	}

	if !vulngateInstalled {
		fmt.Print(ui.RenderError("VulnGate is not installed"))
		fmt.Println()
	}
	if !trivyInstalled {
		fmt.Print(ui.RenderError("Trivy is not installed"))
		fmt.Println()
	}
	fmt.Println(ui.RenderMuted("Run: vulngate install"))
	return nil
}

func isVulngateInInstallDir() bool {
	home, _ := os.UserHomeDir()
	installDir := filepath.Join(home, ".vulngate", "bin")

	vulngateName := "vulngate"
	if runtime.GOOS == "windows" {
		vulngateName = "vulngate.exe"
	}

	_, err := os.Stat(filepath.Join(installDir, vulngateName))
	return err == nil
}

func runInstall(force bool) error {
	home, _ := os.UserHomeDir()
	installDir := filepath.Join(home, ".vulngate", "bin")

	vulngateName := "vulngate"
	if runtime.GOOS == "windows" {
		vulngateName = "vulngate.exe"
	}
	vulngatePath := filepath.Join(installDir, vulngateName)

	vulngateOk := false
	if _, err := os.Stat(vulngatePath); err == nil {
		vulngateOk = true
	}

	trivyOk := trivy.IsInstalled()

	if !force && vulngateOk && trivyOk {
		fmt.Print(ui.RenderSuccess("VulnGate and Trivy are already installed"))
		fmt.Println()

		ver, _ := trivy.Version()
		fmt.Println(ui.RenderMuted(ver))
		fmt.Println()
		fmt.Println(ui.RenderMuted("Run with --force to reinstall"))
		return nil
	}

	fmt.Print(ui.RenderScanStart("VulnGate + Trivy", "install"))

	installer := install.NewInstaller(cfg.Debug)

	if err := installer.Install(); err != nil {
		return err
	}

	fmt.Print(ui.RenderScanComplete(0, "VulnGate and Trivy installed"))
	fmt.Println()

	fmt.Println(ui.RenderMuted(fmt.Sprintf("Location: %s", installDir)))
	fmt.Println()
	fmt.Println(ui.RenderWarning("Restart your terminal or run the following to use now:"))

	if runtime.GOOS == "windows" {
		fmt.Println(ui.RenderMuted(fmt.Sprintf("  $env:PATH = \"%s;\" + $env:PATH", installDir)))
	} else {
		fmt.Println(ui.RenderMuted(fmt.Sprintf("  export PATH=\"%s:$PATH\"", installDir)))
	}

	_ = config.Version

	return nil
}
