package trivy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/leonardo-matheus/vulnscan/internal/log"
)

func IsInstalled() bool {
	if _, err := exec.LookPath("trivy"); err == nil {
		return true
	}

	home, _ := os.UserHomeDir()
	localBin := filepath.Join(home, ".vulngate", "bin")
	trivyName := "trivy"
	if runtime.GOOS == "windows" {
		trivyName = "trivy.exe"
	}

	if _, err := os.Stat(filepath.Join(localBin, trivyName)); err == nil {
		currentPath := os.Getenv("PATH")
		os.Setenv("PATH", localBin+string(os.PathListSeparator)+currentPath)
		return true
	}

	return false
}

func Version() (string, error) {
	cmd := exec.Command("trivy", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get trivy version: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func EnsureInstalled() error {
	if IsInstalled() {
		log.Debug("trivy found in PATH")
		return nil
	}

	return fmt.Errorf("trivy is not installed or not found in PATH\n\n"+
		"Install Trivy automatically:\n"+
		"  vulngate install\n\n"+
		"Or install manually:\n"+
		"  Linux (apt):  sudo apt-get install trivy\n"+
		"  Linux (yum):  sudo yum install trivy\n"+
		"  macOS:        brew install trivy\n"+
		"  Windows:      choco install trivy\n"+
		"  Go:           go install github.com/aquasecurity/trivy/cmd/trivy@latest\n\n"+
		"Documentation: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
}
