package sast

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/leonardo-matheus/vulnscan/internal/log"
)

type Runner struct {
	Debug bool
}

func NewRunner(debug bool) *Runner {
	return &Runner{Debug: debug}
}

func (r *Runner) Run(ctx context.Context, engine Engine, req ScanRequest) (*ScanResult, error) {
	if err := engine.CheckInstalled(); err != nil {
		return nil, err
	}

	args := engine.BuildArgs(req)

	if r.Debug {
		log.Debug("[sast] engine=%s args=%s", engine.Name(), strings.Join(args, " "))
	}

	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = req.TargetPath

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("sast scan timed out after %s", req.Timeout)
	}

	findings, parseErr := engine.ParseOutput(output)
	if parseErr != nil {
		log.Debug("[sast] parse warning: %v", parseErr)
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("failed to execute %s: %w", engine.Name(), err)
		}
	}

	return &ScanResult{
		Engine:    engine.Name(),
		Findings:  findings,
		RawOutput: output,
		ExitCode:  exitCode,
	}, nil
}

func EvaluatePolicy(result *ScanResult, failOn Severity) int {
	blocked := 0
	for _, f := range result.Findings {
		if f.Severity.GreaterOrEqual(failOn) {
			blocked++
		}
	}

	if blocked > 0 {
		return 1
	}
	return 0
}
