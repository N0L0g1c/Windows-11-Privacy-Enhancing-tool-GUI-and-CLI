# One-liner installation script for Windows Privacy Guard
# Downloads and runs the main privacy protection script

param(
    [switch]$All = $false,
    [switch]$Telemetry = $false,
    [switch]$Tracking = $false,
    [switch]$Advertising = $false,
    [switch]$Cortana = $false,
    [switch]$Location = $false,
    [switch]$Bloatware = $false,
    [switch]$Conservative = $false,
    [switch]$Aggressive = $false,
    [switch]$Custom = $false,
    [switch]$Restore = $false,
    [switch]$Debug = $false
)

# Script URL (replace with actual repository URL)
$ScriptUrl = "https://raw.githubusercontent.com/N0L0g1c/Windows-11-Privacy-Enhancing-tool-GUI-and-CLI/main/privacy-guard.ps1"

# Download and execute the main script
try {
    Write-Host "Downloading Windows Privacy Guard..." -ForegroundColor Cyan
    
    # Download the script
    $ScriptContent = Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing
    $ScriptPath = "$env:TEMP\privacy-guard.ps1"
    $ScriptContent.Content | Out-File -FilePath $ScriptPath -Encoding UTF8
    
    # Execute with parameters
    $Arguments = @()
    if ($All) { $Arguments += "--All" }
    if ($Telemetry) { $Arguments += "--Telemetry" }
    if ($Tracking) { $Arguments += "--Tracking" }
    if ($Advertising) { $Arguments += "--Advertising" }
    if ($Cortana) { $Arguments += "--Cortana" }
    if ($Location) { $Arguments += "--Location" }
    if ($Bloatware) { $Arguments += "--Bloatware" }
    if ($Conservative) { $Arguments += "--Conservative" }
    if ($Aggressive) { $Arguments += "--Aggressive" }
    if ($Custom) { $Arguments += "--Custom" }
    if ($Restore) { $Arguments += "--Restore" }
    if ($Debug) { $Arguments += "--Debug" }
    
    Write-Host "Running privacy protection..." -ForegroundColor Green
    & $ScriptPath @Arguments
    
    # Clean up
    Remove-Item $ScriptPath -Force
}
catch {
    Write-Error "Failed to download or run privacy script: $($_.Exception.Message)"
    Write-Host "You can download the script manually from: $ScriptUrl" -ForegroundColor Yellow
}
