package trivy

import (
	"fmt"

	"github.com/leonardo-matheus/vulnscan/internal/config"
)

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

	args = append(args, opts.Target)

	return args
}
