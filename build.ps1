$ErrorActionPreference = "Continue"

$VERSION = "dev"
$COMMIT = "none"

try {
    $v = git describe --tags --always 2>$null
    if ($v) { $VERSION = $v }
} catch {}

try {
    $c = git rev-parse --short HEAD 2>$null
    if ($c) { $COMMIT = $c }
} catch {}

$DATE = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$LDFLAGS = "-s -w -X github.com/leonardo-matheus/vulnscan/internal/config.Version=$VERSION -X github.com/leonardo-matheus/vulnscan/internal/config.Commit=$COMMIT -X github.com/leonardo-matheus/vulnscan/internal/config.Date=$DATE"

Write-Host "Building VulnGate $VERSION ($COMMIT)" -ForegroundColor Cyan

Write-Host "`n[1/4] Windows amd64..." -ForegroundColor Yellow
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags $LDFLAGS -o vulngate.exe .
Write-Host "  -> vulngate.exe" -ForegroundColor Green

Write-Host "`n[2/4] Linux amd64..." -ForegroundColor Yellow
$env:GOOS = "linux"; $env:GOARCH = "amd64"
go build -ldflags $LDFLAGS -o vulngate-linux-amd64 .
Write-Host "  -> vulngate-linux-amd64" -ForegroundColor Green

Write-Host "`n[3/4] Linux arm64..." -ForegroundColor Yellow
$env:GOOS = "linux"; $env:GOARCH = "arm64"
go build -ldflags $LDFLAGS -o vulngate-linux-arm64 .
Write-Host "  -> vulngate-linux-arm64" -ForegroundColor Green

Write-Host "`n[4/4] macOS..." -ForegroundColor Yellow
$env:GOOS = "darwin"; $env:GOARCH = "amd64"
go build -ldflags $LDFLAGS -o vulngate-darwin-amd64 .
$env:GOOS = "darwin"; $env:GOARCH = "arm64"
go build -ldflags $LDFLAGS -o vulngate-darwin-arm64 .
Write-Host "  -> vulngate-darwin-amd64, vulngate-darwin-arm64" -ForegroundColor Green

$env:GOOS = $null; $env:GOARCH = $null

Write-Host "`nBuild complete!" -ForegroundColor Cyan
Get-ChildItem vulngate* | Format-Table Name, @{N="Size (MB)";E={[math]::Round($_.Length/1MB,1)}} -AutoSize
