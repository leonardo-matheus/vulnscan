package install

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/leonardo-matheus/vulnscan/internal/log"
)

const (
	trivyRepo    = "aquasecurity/trivy"
	releasesBase = "https://github.com"
)

type Installer struct {
	InstallDir string
	Verbose    bool
}

func NewInstaller(verbose bool) *Installer {
	home, _ := os.UserHomeDir()
	installDir := filepath.Join(home, ".vulngate", "bin")

	return &Installer{
		InstallDir: installDir,
		Verbose:    verbose,
	}
}

func (i *Installer) Install() error {
	if err := os.MkdirAll(i.InstallDir, 0755); err != nil {
		return fmt.Errorf("failed to create install directory: %w", err)
	}

	log.Info("Installing VulnGate...")
	if err := i.installSelf(); err != nil {
		log.Warn("Could not install VulnGate: %v", err)
	}

	arch := runtime.GOARCH
	platform := runtime.GOOS

	log.Info("Platform: %s/%s", platform, arch)

	downloadURL, filename, err := i.getDownloadURL(platform, arch)
	if err != nil {
		return err
	}

	log.Info("Download URL: %s", downloadURL)

	zipPath := filepath.Join(i.InstallDir, filename)

	log.Info("Downloading Trivy...")
	if err := i.download(downloadURL, zipPath); err != nil {
		return err
	}

	log.Info("Extracting...")
	if err := i.extract(zipPath); err != nil {
		return err
	}

	os.Remove(zipPath)

	trivyPath := i.getTrivyPath()
	if _, err := os.Stat(trivyPath); os.IsNotExist(err) {
		return fmt.Errorf("trivy binary not found after extraction at %s", trivyPath)
	}

	log.Info("Trivy installed successfully at: %s", trivyPath)

	if err := i.addToPath(); err != nil {
		log.Warn("Could not auto-add to PATH: %v", err)
		log.Info("Please add manually: %s", i.InstallDir)
	}

	return nil
}

func (i *Installer) installSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not locate vulngate binary: %w", err)
	}

	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("could not resolve vulngate path: %w", err)
	}

	vulngateName := "vulngate"
	if runtime.GOOS == "windows" {
		vulngateName = "vulngate.exe"
	}

	dest := filepath.Join(i.InstallDir, vulngateName)

	if exe == dest {
		log.Debug("VulnGate already in install directory")
	} else {
		if err := copyFile(exe, dest); err != nil {
			return fmt.Errorf("could not copy vulngate: %w", err)
		}
		log.Info("VulnGate installed at: %s", dest)
	}

	if err := i.createVGAlias(); err != nil {
		log.Warn("Could not create vg alias: %v", err)
	}

	return nil
}

func (i *Installer) createVGAlias() error {
	if runtime.GOOS == "windows" {
		return i.createVGAliasWindows()
	}
	return i.createVGAliasUnix()
}

func (i *Installer) createVGAliasWindows() error {
	vulngateExe := filepath.Join(i.InstallDir, "vulngate.exe")

	vgBat := filepath.Join(i.InstallDir, "vg.bat")
	batContent := fmt.Sprintf("@echo off\r\n\"%s\" %%*\r\n", vulngateExe)
	if err := os.WriteFile(vgBat, []byte(batContent), 0755); err != nil {
		return fmt.Errorf("could not create vg.bat: %w", err)
	}
	log.Info("Created vg.bat for CMD: %s", vgBat)

	vgPs1 := filepath.Join(i.InstallDir, "vg.ps1")
	ps1Content := fmt.Sprintf("& \"%s\" @args\n", vulngateExe)
	if err := os.WriteFile(vgPs1, []byte(ps1Content), 0755); err != nil {
		return fmt.Errorf("could not create vg.ps1: %w", err)
	}
	log.Info("Created vg.ps1 for PowerShell: %s", vgPs1)

	return nil
}

func (i *Installer) createVGAliasUnix() error {
	vulngateBin := filepath.Join(i.InstallDir, "vulngate")
	vgLink := filepath.Join(i.InstallDir, "vg")

	if _, err := os.Lstat(vgLink); err == nil {
		os.Remove(vgLink)
	}

	if err := os.Symlink(vulngateBin, vgLink); err != nil {
		return fmt.Errorf("could not create vg symlink: %w", err)
	}

	log.Info("Created vg alias: %s", vgLink)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, info.Mode())
}

func (i *Installer) getDownloadURL(platform, arch string) (string, string, error) {
	latestVersion, err := i.getLatestVersion()
	if err != nil {
		return "", "", fmt.Errorf("failed to get latest version: %w", err)
	}

	versionNum := strings.TrimPrefix(latestVersion, "v")

	var osName, archSuffix, ext string

	switch platform {
	case "windows":
		osName = "windows"
		ext = "zip"
	case "darwin":
		osName = "macOS"
		ext = "tar.gz"
	case "linux":
		osName = "Linux"
		ext = "tar.gz"
	default:
		return "", "", fmt.Errorf("unsupported platform: %s", platform)
	}

	switch arch {
	case "amd64":
		archSuffix = "64bit"
	case "arm64":
		archSuffix = "ARM64"
	default:
		return "", "", fmt.Errorf("unsupported architecture: %s", arch)
	}

	filename := fmt.Sprintf("trivy_%s_%s-%s.%s", versionNum, osName, archSuffix, ext)
	url := fmt.Sprintf("%s/%s/releases/download/%s/%s", releasesBase, trivyRepo, latestVersion, filename)

	return url, filename, nil
}

func (i *Installer) getLatestVersion() (string, error) {
	url := fmt.Sprintf("%s/%s/releases/latest", releasesBase, trivyRepo)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		parts := strings.Split(location, "/")
		if len(parts) > 0 {
			version := parts[len(parts)-1]
			if strings.HasPrefix(version, "v") {
				return version, nil
			}
			return "v" + version, nil
		}
	}

	return "", fmt.Errorf("could not determine latest version")
}

func (i *Installer) download(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	total := resp.ContentLength
	if total > 0 {
		log.Info("Size: %.1f MB", float64(total)/(1024*1024))
	}

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	log.Info("Downloaded: %.1f MB", float64(written)/(1024*1024))

	return nil
}

func (i *Installer) extract(zipPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(i.InstallDir, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

func (i *Installer) getTrivyPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(i.InstallDir, "trivy.exe")
	}
	return filepath.Join(i.InstallDir, "trivy")
}

func (i *Installer) addToPath() error {
	currentPath := os.Getenv("PATH")
	if strings.Contains(currentPath, i.InstallDir) {
		log.Info("Install directory already in PATH")
		return nil
	}

	switch runtime.GOOS {
	case "windows":
		return i.addToPathWindows()
	case "darwin":
		return i.addToPathUnix("~/.zshrc", "~/.bash_profile")
	default:
		return i.addToPathUnix("~/.bashrc", "~/.profile")
	}
}

func (i *Installer) addToPathWindows() error {
	psCmd := fmt.Sprintf(`
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*%s*") {
    [Environment]::SetEnvironmentVariable("Path", "%s;" + $currentPath, "User")
    Write-Output "PATH updated"
} else {
    Write-Output "Already in PATH"
}
`, i.InstallDir, i.InstallDir)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update PATH: %w", err)
	}

	log.Info("PATH: %s", strings.TrimSpace(string(output)))

	currentPath := os.Getenv("PATH")
	os.Setenv("PATH", i.InstallDir+";"+currentPath)

	i.addPowerShellAlias()

	return nil
}

func (i *Installer) addPowerShellAlias() {
	home, _ := os.UserHomeDir()
	profilePath := filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(profilePath), 0755)
	}

	content, _ := os.ReadFile(profilePath)
	contentStr := string(content)

	aliasLine := fmt.Sprintf("\n# VulnGate alias\nfunction vg { & \"%s\" @args }\n", filepath.Join(i.InstallDir, "vulngate.exe"))
	if strings.Contains(contentStr, "function vg") {
		return
	}

	f, err := os.OpenFile(profilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Warn("Could not update PowerShell profile: %v", err)
		return
	}
	f.WriteString(aliasLine)
	f.Close()

	log.Info("Added vg function to PowerShell profile: %s", profilePath)
}

func (i *Installer) addToPathUnix(rcFiles ...string) error {
	for _, rcFile := range rcFiles {
		expanded := rcFile
		if strings.HasPrefix(rcFile, "~") {
			home, _ := os.UserHomeDir()
			expanded = filepath.Join(home, rcFile[1:])
		}

		line := fmt.Sprintf("\n# VulnGate\nexport PATH=\"%s:$PATH\"\n", i.InstallDir)

		content, _ := os.ReadFile(expanded)
		if strings.Contains(string(content), i.InstallDir) {
			continue
		}

		f, err := os.OpenFile(expanded, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			continue
		}
		f.WriteString(line)
		f.Close()

		log.Info("Added to %s", rcFile)
	}

	currentPath := os.Getenv("PATH")
	os.Setenv("PATH", i.InstallDir+":"+currentPath)

	return nil
}
