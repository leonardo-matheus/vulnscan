package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/leonardo-matheus/vulnscan/internal/ui"
)

type TrivyReport struct {
	Results []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target          string              `json:"Target"`
	Class           string              `json:"Class"`
	Type            string              `json:"Type"`
	Vulnerabilities []TrivyVuln         `json:"Vulnerabilities"`
	Secrets         []TrivySecret       `json:"Secrets"`
	Misconfigurations []TrivyMisconfig  `json:"Misconfigurations"`
}

type TrivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	Severity        string `json:"Severity"`
	FixedVersion    string `json:"FixedVersion"`
}

type TrivySecret struct {
	Title string `json:"Title"`
}

type TrivyMisconfig struct {
	ID       string `json:"ID"`
	Severity string `json:"Severity"`
	Title    string `json:"Title"`
}

func ParseReport(jsonPath string) (*ui.ScanSummary, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	summary := &ui.ScanSummary{}

	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			summary.VulnTotal++
			switch strings.ToUpper(v.Severity) {
			case "CRITICAL":
				summary.VulnCritical++
			case "HIGH":
				summary.VulnHigh++
			case "MEDIUM":
				summary.VulnMedium++
			case "LOW":
				summary.VulnLow++
			default:
				summary.VulnUnknown++
			}
		}

		for range result.Secrets {
			summary.SecretTotal++
		}

		for _, m := range result.Misconfigurations {
			summary.MisconfigTotal++
			switch strings.ToUpper(m.Severity) {
			case "CRITICAL":
				summary.MisconfigCritical++
			case "HIGH":
				summary.MisconfigHigh++
			}
		}
	}

	return summary, nil
}

func BuildJSONArgs(args []string, outputPath string) []string {
	jsonArgs := make([]string, len(args))
	copy(jsonArgs, args)

	for i, arg := range jsonArgs {
		if arg == "--format" && i+1 < len(jsonArgs) {
			jsonArgs[i+1] = "json"
			break
		}
		if arg == "--format" {
			continue
		}
	}

	hasFormat := false
	for _, arg := range jsonArgs {
		if arg == "--format" {
			hasFormat = true
			break
		}
	}
	if !hasFormat {
		newArgs := make([]string, 0, len(jsonArgs)+2)
		newArgs = append(newArgs, jsonArgs[:len(jsonArgs)-1]...)
		newArgs = append(newArgs, "--format", "json")
		newArgs = append(newArgs, jsonArgs[len(jsonArgs)-1])
		jsonArgs = newArgs
	}

	hasOutput := false
	for i, arg := range jsonArgs {
		if arg == "--output" {
			if i+1 < len(jsonArgs) {
				jsonArgs[i+1] = outputPath
			}
			hasOutput = true
			break
		}
	}
	if !hasOutput {
		newArgs := make([]string, 0, len(jsonArgs)+2)
		newArgs = append(newArgs, jsonArgs[:len(jsonArgs)-1]...)
		newArgs = append(newArgs, "--output", outputPath)
		newArgs = append(newArgs, jsonArgs[len(jsonArgs)-1])
		jsonArgs = newArgs
	}

	return jsonArgs
}

func GetReportDir() string {
	home, _ := os.UserHomeDir()

	if runtime.GOOS == "windows" {
		return filepath.Join(home, "Documents", "vulngate")
	}
	return filepath.Join(home, ".vulngate", "reports")
}

func GenerateReportPath(target string) string {
	dir := GetReportDir()
	os.MkdirAll(dir, 0755)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	safeName := strings.ReplaceAll(target, ":", "")
	safeName = strings.ReplaceAll(safeName, "\\", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	if len(safeName) > 50 {
		safeName = safeName[len(safeName)-50:]
	}

	return filepath.Join(dir, fmt.Sprintf("scan_%s_%s.json", safeName, timestamp))
}

func GenerateSARIFPath(target string) string {
	dir := GetReportDir()
	os.MkdirAll(dir, 0755)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	safeName := strings.ReplaceAll(target, ":", "")
	safeName = strings.ReplaceAll(safeName, "\\", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	if len(safeName) > 50 {
		safeName = safeName[len(safeName)-50:]
	}

	return filepath.Join(dir, fmt.Sprintf("scan_%s_%s.sarif", safeName, timestamp))
}

func BuildSARIFArgs(args []string, outputPath string) []string {
	sarifArgs := make([]string, len(args))
	copy(sarifArgs, args)

	for i, arg := range sarifArgs {
		if arg == "--format" && i+1 < len(sarifArgs) {
			sarifArgs[i+1] = "sarif"
			break
		}
	}

	hasFormat := false
	for _, arg := range sarifArgs {
		if arg == "--format" {
			hasFormat = true
			break
		}
	}
	if !hasFormat {
		newArgs := make([]string, 0, len(sarifArgs)+2)
		newArgs = append(newArgs, sarifArgs[:len(sarifArgs)-1]...)
		newArgs = append(newArgs, "--format", "sarif")
		newArgs = append(newArgs, sarifArgs[len(sarifArgs)-1])
		sarifArgs = newArgs
	}

	hasOutput := false
	for i, arg := range sarifArgs {
		if arg == "--output" {
			if i+1 < len(sarifArgs) {
				sarifArgs[i+1] = outputPath
			}
			hasOutput = true
			break
		}
	}
	if !hasOutput {
		newArgs := make([]string, 0, len(sarifArgs)+2)
		newArgs = append(newArgs, sarifArgs[:len(sarifArgs)-1]...)
		newArgs = append(newArgs, "--output", outputPath)
		newArgs = append(newArgs, sarifArgs[len(sarifArgs)-1])
		sarifArgs = newArgs
	}

	return sarifArgs
}
