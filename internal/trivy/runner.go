package trivy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
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

func (r *Runner) Run(args []string) (int, error) {
	return r.RunWithTarget(args)
}

func (r *Runner) RunWithTarget(args []string) (int, error) {
	cmd := exec.Command("trivy", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if r.Debug {
		log.Debug("executing: trivy %s", strings.Join(args, " "))
	}

	err := cmd.Run()

	if stdout.Len() > 0 {
		fmt.Fprint(os.Stdout, stdout.String())
	}

	if stderr.Len() > 0 {
		fmt.Fprint(os.Stderr, stderr.String())
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if r.Debug {
				log.Debug("trivy exited with code %d", code)
			}
			return code, nil
		}
		return -1, fmt.Errorf("failed to execute trivy: %w", err)
	}

	if r.Debug {
		log.Debug("trivy exited with code 0")
	}
	return 0, nil
}

func (r *Runner) RunWithProgress(args []string, onPhase func(string, int)) (int, error) {
	cmd := exec.Command("trivy", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return -1, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if r.Debug {
		log.Debug("executing: trivy %s", strings.Join(args, " "))
	}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("failed to start trivy: %w", err)
	}

	var outputBuf bytes.Buffer

	go r.parseProgress(stdout, &outputBuf, onPhase)
	go r.drainOutput(stderr, nil)

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if outputBuf.Len() > 0 {
				fmt.Fprint(os.Stdout, outputBuf.String())
			}
			return code, nil
		}
		return -1, fmt.Errorf("failed to execute trivy: %w", err)
	}

	if outputBuf.Len() > 0 {
		fmt.Fprint(os.Stdout, outputBuf.String())
	}

	return 0, nil
}

func (r *Runner) parseProgress(reader io.Reader, buf *bytes.Buffer, onPhase func(string, int)) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	phaseMap := map[string]int{
		"vulndb":             1,
		"Downloading":        1,
		"Need to update":     1,
		"vulnerability scanning": 2,
		"[vuln]":             2,
		"[misconfig]":        2,
		"[secret]":           2,
		"Detecting":          3,
		"language-specific":  3,
		"config files":       3,
		"Number of":          3,
		"Report Summary":     4,
		"Target":             4,
		"Table":              4,
	}

	currentPhase := 0

	for scanner.Scan() {
		line := scanner.Text()
		buf.WriteString(line + "\n")

		lower := strings.ToLower(line)
		for keyword, phase := range phaseMap {
			if strings.Contains(lower, strings.ToLower(keyword)) && phase > currentPhase {
				currentPhase = phase
				if onPhase != nil {
					phaseName := getPhaseName(phase)
					onPhase(phaseName, phase)
				}
				break
			}
		}
	}
}

func (r *Runner) drainOutput(reader io.Reader, buf *bytes.Buffer) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if buf != nil {
			buf.WriteString(line + "\n")
		}
	}
}

func getPhaseName(phase int) string {
	switch phase {
	case 1:
		return "Downloading vulnerability DB"
	case 2:
		return "Scanning vulnerabilities"
	case 3:
		return "Analyzing dependencies"
	case 4:
		return "Generating report"
	default:
		return "Processing"
	}
}
