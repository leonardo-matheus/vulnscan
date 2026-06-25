package trivy

import (
	"fmt"
	"strings"

	"github.com/leonardo-matheus/vulnscan/internal/config"
)

var defaultSkipDirs = []string{
	"node_modules",
	"vendor",
	"target",
	"build",
	".git",
	".svn",
	".hg",
	"dist",
	"__pycache__",
	".venv",
	"venv",
}

func BuildFSArgs(opts config.ScanOptions) []string {
	args := []string{"fs"}

	args = append(args, "--scanners", config.ScannerString(opts.Scanners))
	args = append(args, "--severity", config.SeverityString(opts.Severity))
	args = append(args, "--exit-code", fmt.Sprintf("%d", opts.ExitCode))
	args = append(args, "--format", string(opts.Format))

	if opts.Output != "" {
		args = append(args, "--output", opts.Output)
	}

	if opts.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	if opts.IncludeDevDeps {
		args = append(args, "--include-dev-deps")
	}

	if opts.Timeout != "" {
		args = append(args, "--timeout", opts.Timeout)
	}

	if opts.Debug {
		args = append(args, "--debug")
	}

	if !opts.SkipDefaultDirs {
		for _, d := range defaultSkipDirs {
			args = append(args, "--skip-dirs", d)
		}
	}

	if opts.ExtraSkipDirs != "" {
		for _, d := range strings.Split(opts.ExtraSkipDirs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				args = append(args, "--skip-dirs", d)
			}
		}
	}

	args = append(args, opts.Target)

	return args
}
