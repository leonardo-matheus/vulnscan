package output

import (
	"fmt"
	"os"
	"path/filepath"
)

func EnsureOutputDir(outputPath string) error {
	if outputPath == "" {
		return nil
	}

	dir := filepath.Dir(outputPath)
	if dir == "" || dir == "." {
		return nil
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", dir, err)
		}
	}

	return nil
}
