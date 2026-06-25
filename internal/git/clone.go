package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/leonardo-matheus/vulnscan/internal/log"
)

func CloneTemp(url string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "vulngate-repo-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	cleanup := func() {
		log.Debug("cleaning up temp clone: %s", tmpDir)
		os.RemoveAll(tmpDir)
	}

	log.Debug("cloning %s into %s", url, tmpDir)

	cmd := exec.Command("git", "clone", "--depth", "1", url, tmpDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	return tmpDir, cleanup, nil
}

func IsGitURL(url string) bool {
	return len(url) > 4 && (filepath.Base(url) != url || filepath.Ext(url) == "")
}
