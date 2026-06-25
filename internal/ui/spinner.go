package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerStyle  = lipgloss.NewStyle().Foreground(ColorPrimary)
	elapsedStyle  = lipgloss.NewStyle().Foreground(ColorMuted)
	timeStyle     = lipgloss.NewStyle().Foreground(ColorAccent)
)

type ScanProgress struct {
	title    string
	target   string
	start    time.Time
	stop     chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	phase    string
	phaseNum int
	totalPhases int
}

func NewScanProgress(title, target string) *ScanProgress {
	return &ScanProgress{
		title:       title,
		target:      target,
		start:       time.Now(),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		totalPhases: 5,
	}
}

func (s *ScanProgress) SetPhase(phase string, num int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = phase
	s.phaseNum = num
}

func (s *ScanProgress) Start() {
	go s.render()
}

func (s *ScanProgress) Stop() {
	close(s.stop)
	<-s.done
}

func (s *ScanProgress) render() {
	defer close(s.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	frameIdx := 0

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			phase := s.phase
			phaseNum := s.phaseNum
			s.mu.Unlock()

			elapsed := time.Since(s.start)
			elapsedStr := formatDuration(elapsed)

			spinner := spinnerStyle.Render(spinnerFrames[frameIdx])
			frameIdx = (frameIdx + 1) % len(spinnerFrames)

			percent := 0
			if s.totalPhases > 0 {
				percent = (phaseNum * 100) / s.totalPhases
			}
			progress := renderProgressBar(percent)

			line1 := fmt.Sprintf("  %s  %s", spinner, StyleCardHeader.Render("Scanning..."))
			line2 := fmt.Sprintf("     %s %s", StyleMuted.Render("Target:  "), StyleHighlight.Render(s.target))
			line3 := fmt.Sprintf("     %s %s", StyleMuted.Render("Type:    "), s.title)
			line4 := fmt.Sprintf("     %s %s  %s %s  %s",
				StyleMuted.Render("Phase:   "),
				phase,
				StyleMuted.Render("Elapsed:"),
				timeStyle.Render(elapsedStr),
				StyleMuted.Render(fmt.Sprintf("(%.0fs)", elapsed.Seconds())),
			)
			line5 := fmt.Sprintf("     %s", progress)

			clearLines(5)
			fmt.Print(line1 + "\n" + line2 + "\n" + line3 + "\n" + line4 + "\n" + line5 + "\n")
		}
	}
}

func (s *ScanProgress) Finish(exitCode int) {
	elapsed := time.Since(s.start)
	elapsedStr := formatDuration(elapsed)

	clearLines(5)

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(StyleCardHeader.Render("  Scan Results"))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("     %s %s\n", StyleMuted.Render("Target:  "), StyleHighlight.Render(s.target)))
	b.WriteString(fmt.Sprintf("     %s %s\n", StyleMuted.Render("Type:    "), s.title))
	b.WriteString(fmt.Sprintf("     %s %s\n", StyleMuted.Render("Time:    "), timeStyle.Render(elapsedStr)))

	if exitCode > 0 {
		b.WriteString(fmt.Sprintf("     %s %s\n\n", StyleMuted.Render("Status:  "), StyleError.Render("Vulnerabilities found")))
	} else {
		b.WriteString(fmt.Sprintf("     %s %s\n\n", StyleMuted.Render("Status:  "), StyleSuccess.Render("No vulnerabilities found")))
	}

	fmt.Print(b.String())
}

func renderProgressBar(percent int) string {
	width := 40
	filled := (width * percent) / 100
	empty := width - filled

	bar := lipgloss.NewStyle().Foreground(ColorPrimary).Render(strings.Repeat("█", filled))
	gap := lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("░", empty))
	pct := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render(fmt.Sprintf(" %3d%%", percent))

	return bar + gap + pct
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func clearLines(n int) {
	for i := 0; i < n; i++ {
		fmt.Print("\033[1A\033[2K")
	}
}
