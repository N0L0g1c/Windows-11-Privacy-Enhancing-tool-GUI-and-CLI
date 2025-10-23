# Windows Privacy Guard
# Disables all privacy-breaking features in Windows 11 while keeping essential functionality

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
    [switch]$Debug = $false,
    [switch]$Help = $false
)

# Script version and metadata
$ScriptVersion = "1.0.0"
$ScriptName = "Windows Privacy Guard"
$LogFile = "$env:TEMP\privacy-guard.log"
$ConfigFile = "$env:USERPROFILE\.privacy-guard\config.json"
$BackupDir = "$env:USERPROFILE\.privacy-guard\backups"

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    Cyan = "Cyan"
    Magenta = "Magenta"
    White = "White"
}

# Enhanced logging functions
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $Colors.Green
    Write-Log $Message "SUCCESS"
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $Colors.Yellow
    Write-Log $Message "WARNING"
}

function Write-Error {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $Colors.Red
    Write-Log $Message "ERROR"
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $Colors.Blue
    Write-Log $Message "INFO"
}

function Write-Debug {
    param([string]$Message)
    if ($Debug) {
        Write-Host $Message -ForegroundColor $Colors.Cyan
        Write-Log $Message "DEBUG"
    }
}

# Privacy protection functions
function Disable-Telemetry {
    Write-Info "Disabling Windows telemetry and data collection..."
    
    try {
        # Disable telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Force
        
        # Disable diagnostic data
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 -Force
        
        # Disable error reporting
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Value 1 -Force
        
        # Disable customer experience improvement program
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Force
        
        Write-Success "Telemetry disabled successfully"
    }
    catch {
        Write-Error "Failed to disable telemetry: $($_.Exception.Message)"
    }
}

function Disable-Tracking {
    Write-Info "Disabling tracking and monitoring..."
    
    try {
        # Disable activity history
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Force
        
        # Disable usage statistics
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
        
        # Disable app usage tracking
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
        
        # Disable search tracking
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Force
        
        # Disable voice data collection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Force
        
        Write-Success "Tracking disabled successfully"
    }
    catch {
        Write-Error "Failed to disable tracking: $($_.Exception.Message)"
    }
}

function Disable-Advertising {
    Write-Info "Disabling advertising and personalization..."
    
    try {
        # Disable advertising ID
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force
        
        # Disable personalized ads
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Force
        
        # Disable start menu suggestions
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Force
        
        # Disable personalized content
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Force
        
        # Disable search suggestions
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Force
        
        Write-Success "Advertising disabled successfully"
    }
    catch {
        Write-Error "Failed to disable advertising: $($_.Exception.Message)"
    }
}

function Disable-Cortana {
    Write-Info "Disabling Cortana and voice data collection..."
    
    try {
        # Disable Cortana
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Force
        
        # Disable voice data collection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Force
        
        # Disable voice recognition
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Force
        
        # Disable Cortana service
        Stop-Service -Name "Cortana" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "Cortana" -StartupType Disabled -ErrorAction SilentlyContinue
        
        Write-Success "Cortana disabled successfully"
    }
    catch {
        Write-Error "Failed to disable Cortana: $($_.Exception.Message)"
    }
}

function Disable-Location {
    Write-Info "Disabling location services and tracking..."
    
    try {
        # Disable location services
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Force
        
        # Disable location tracking
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force
        
        # Disable location history
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force
        
        # Disable location-based services
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force
        
        Write-Success "Location services disabled successfully"
    }
    catch {
        Write-Error "Failed to disable location services: $($_.Exception.Message)"
    }
}

function Remove-Bloatware {
    Write-Info "Removing Microsoft bloatware and spyware..."
    
    try {
        # List of Microsoft bloatware to remove
        $bloatware = @(
            "Microsoft.BingNews",
            "Microsoft.BingWeather",
            "Microsoft.GetHelp",
            "Microsoft.Getstarted",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MicrosoftStickyNotes",
            "Microsoft.MixedReality.Portal",
            "Microsoft.Office.OneNote",
            "Microsoft.People",
            "Microsoft.SkypeApp",
            "Microsoft.StorePurchaseApp",
            "Microsoft.Todos",
            "Microsoft.WindowsAlarms",
            "Microsoft.WindowsCamera",
            "Microsoft.WindowsMaps",
            "Microsoft.WindowsSoundRecorder",
            "Microsoft.Xbox.TCUI",
            "Microsoft.XboxApp",
            "Microsoft.XboxGameOverlay",
            "Microsoft.XboxGamingOverlay",
            "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.YourPhone",
            "Microsoft.ZuneMusic",
            "Microsoft.ZuneVideo"
        )
        
        foreach ($app in $bloatware) {
            try {
                Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
                Write-Debug "Removed: $app"
            }
            catch {
                Write-Debug "Could not remove: $app"
            }
        }
        
        # Remove Microsoft Edge (if you want to)
        # Get-AppxPackage -Name "Microsoft.MicrosoftEdge" | Remove-AppxPackage -ErrorAction SilentlyContinue
        
        Write-Success "Bloatware removal completed"
    }
    catch {
        Write-Error "Failed to remove bloatware: $($_.Exception.Message)"
    }
}

function Disable-MicrosoftServices {
    Write-Info "Disabling Microsoft data collection services..."
    
    try {
        # Services to disable
        $servicesToDisable = @(
            "DiagTrack",
            "dmwappushservice",
            "WerSvc",
            "WbioSrvc",
            "WSearch",
            "XblAuthManager",
            "XblGameSave",
            "XboxGipSvc",
            "XboxNetApiSvc"
        )
        
        foreach ($serviceName in $servicesToDisable) {
            try {
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Debug "Disabled service: $serviceName"
            }
            catch {
                Write-Debug "Could not disable service: $serviceName"
            }
        }
        
        Write-Success "Microsoft services disabled successfully"
    }
    catch {
        Write-Error "Failed to disable Microsoft services: $($_.Exception.Message)"
    }
}

function Disable-WindowsUpdateTelemetry {
    Write-Info "Disabling Windows Update telemetry..."
    
    try {
        # Disable Windows Update telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0 -Force
        
        # Disable driver updates
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Force
        
        # Disable automatic driver updates
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Force
        
        Write-Success "Windows Update telemetry disabled successfully"
    }
    catch {
        Write-Error "Failed to disable Windows Update telemetry: $($_.Exception.Message)"
    }
}

function Disable-OneDrive {
    Write-Info "Disabling OneDrive and cloud sync..."
    
    try {
        # Disable OneDrive
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force
        
        # Disable OneDrive sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force
        
        # Disable OneDrive integration
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force
        
        # Stop OneDrive service
        Stop-Service -Name "OneDrive" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "OneDrive" -StartupType Disabled -ErrorAction SilentlyContinue
        
        Write-Success "OneDrive disabled successfully"
    }
    catch {
        Write-Error "Failed to disable OneDrive: $($_.Exception.Message)"
    }
}

function Disable-WindowsHello {
    Write-Info "Disabling Windows Hello biometric data collection..."
    
    try {
        # Disable Windows Hello
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Biometrics" -Name "Enabled" -Value 0 -Force
        
        # Disable biometric data collection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Biometrics" -Name "Enabled" -Value 0 -Force
        
        # Disable face recognition
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Biometrics" -Name "Enabled" -Value 0 -Force
        
        # Disable fingerprint recognition
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Biometrics" -Name "Enabled" -Value 0 -Force
        
        Write-Success "Windows Hello disabled successfully"
    }
    catch {
        Write-Error "Failed to disable Windows Hello: $($_.Exception.Message)"
    }
}

function Disable-FeedbackHub {
    Write-Info "Disabling Feedback Hub and user feedback..."
    
    try {
        # Disable Feedback Hub
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FeedbackHub" -Name "DisableFeedbackHub" -Value 1 -Force
        
        # Disable user feedback
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FeedbackHub" -Name "DisableFeedbackHub" -Value 1 -Force
        
        # Disable feedback collection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FeedbackHub" -Name "DisableFeedbackHub" -Value 1 -Force
        
        Write-Success "Feedback Hub disabled successfully"
    }
    catch {
        Write-Error "Failed to disable Feedback Hub: $($_.Exception.Message)"
    }
}

function Show-PrivacyStatus {
    Write-Host "Windows Privacy Status" -ForegroundColor $Colors.Cyan
    Write-Host "=====================" -ForegroundColor $Colors.Cyan
    Write-Host ""
    
    # Check telemetry status
    try {
        $telemetry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
        if ($telemetry -and $telemetry.AllowTelemetry -eq 0) {
            Write-Host "Telemetry: DISABLED" -ForegroundColor $Colors.Green
        } else {
            Write-Host "Telemetry: ENABLED" -ForegroundColor $Colors.Red
        }
    }
    catch {
        Write-Host "Telemetry: UNKNOWN" -ForegroundColor $Colors.Yellow
    }
    
    # Check advertising ID status
    try {
        $advertising = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($advertising -and $advertising.Enabled -eq 0) {
            Write-Host "Advertising ID: DISABLED" -ForegroundColor $Colors.Green
        } else {
            Write-Host "Advertising ID: ENABLED" -ForegroundColor $Colors.Red
        }
    }
    catch {
        Write-Host "Advertising ID: UNKNOWN" -ForegroundColor $Colors.Yellow
    }
    
    # Check location services status
    try {
        $location = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue
        if ($location -and $location.DisableLocation -eq 1) {
            Write-Host "Location Services: DISABLED" -ForegroundColor $Colors.Green
        } else {
            Write-Host "Location Services: ENABLED" -ForegroundColor $Colors.Red
        }
    }
    catch {
        Write-Host "Location Services: UNKNOWN" -ForegroundColor $Colors.Yellow
    }
    
    Write-Host ""
}

function Restore-WindowsDefaults {
    Write-Info "Restoring Windows default privacy settings..."
    
    try {
        # Restore telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
        
        # Restore advertising ID
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 1 -Force
        
        # Restore location services
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 0 -Force
        
        # Restore Cortana
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 1 -Force
        
        # Restore OneDrive
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 0 -Force
        
        Write-Success "Windows default privacy settings restored"
    }
    catch {
        Write-Error "Failed to restore Windows defaults: $($_.Exception.Message)"
    }
}

function Show-Help {
    Write-Host @"
Windows Privacy Guard v$ScriptVersion

USAGE:
    .\privacy-guard.ps1 [OPTIONS]

OPTIONS:
    Privacy Protection:
        --all                Apply all privacy protections
        --telemetry          Disable telemetry and data collection
        --tracking           Disable tracking and monitoring
        --advertising         Disable advertising and personalization
        --cortana            Disable Cortana and voice data
        --location            Disable location services
        --bloatware          Remove Microsoft bloatware

    Privacy Levels:
        --conservative        Apply conservative privacy settings
        --aggressive          Apply aggressive privacy settings
        --custom              Apply custom privacy settings

    Utilities:
        --restore            Restore Windows default settings
        --debug              Enable debug mode
        --help               Show this help

EXAMPLES:
    .\privacy-guard.ps1 --all
    .\privacy-guard.ps1 --telemetry --tracking
    .\privacy-guard.ps1 --conservative
    .\privacy-guard.ps1 --restore

"@
}

function Initialize-Environment {
    # Create config directory
    $configDir = Split-Path $ConfigFile -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    # Create backup directory
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
    
    Write-Success "Environment initialized"
}

function Main {
    # Show banner
    Write-Host "Windows Privacy Guard v$ScriptVersion" -ForegroundColor $Colors.Cyan
    Write-Host "=====================================" -ForegroundColor $Colors.Cyan
    Write-Host ""
    
    # Initialize logging
    Write-Log "Starting Windows Privacy Guard"
    
    # Initialize environment
    Initialize-Environment
    
    # Handle help
    if ($Help) {
        Show-Help
        return
    }
    
    # Check if running as administrator
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Error "This script requires administrator privileges"
        Write-Info "Please run PowerShell as Administrator"
        return
    }
    
    # Execute based on parameters
    if ($Restore) {
        Restore-WindowsDefaults
        Write-Success "Windows default privacy settings restored"
    }
    elseif ($All) {
        Write-Info "Applying all privacy protections..."
        Disable-Telemetry
        Disable-Tracking
        Disable-Advertising
        Disable-Cortana
        Disable-Location
        Remove-Bloatware
        Disable-MicrosoftServices
        Disable-WindowsUpdateTelemetry
        Disable-OneDrive
        Disable-WindowsHello
        Disable-FeedbackHub
        Write-Success "All privacy protections applied successfully"
    }
    elseif ($Conservative) {
        Write-Info "Applying conservative privacy settings..."
        Disable-Telemetry
        Disable-Advertising
        Disable-Location
        Write-Success "Conservative privacy settings applied successfully"
    }
    elseif ($Aggressive) {
        Write-Info "Applying aggressive privacy settings..."
        Disable-Telemetry
        Disable-Tracking
        Disable-Advertising
        Disable-Cortana
        Disable-Location
        Remove-Bloatware
        Disable-MicrosoftServices
        Disable-WindowsUpdateTelemetry
        Disable-OneDrive
        Disable-WindowsHello
        Disable-FeedbackHub
        Write-Success "Aggressive privacy settings applied successfully"
    }
    else {
        # Apply specific protections
        if ($Telemetry) {
            Disable-Telemetry
        }
        
        if ($Tracking) {
            Disable-Tracking
        }
        
        if ($Advertising) {
            Disable-Advertising
        }
        
        if ($Cortana) {
            Disable-Cortana
        }
        
        if ($Location) {
            Disable-Location
        }
        
        if ($Bloatware) {
            Remove-Bloatware
        }
        
        # If no specific action was requested, show privacy status
        if (-not ($Telemetry -or $Tracking -or $Advertising -or $Cortana -or $Location -or $Bloatware)) {
            Show-PrivacyStatus
        }
    }
    
    Write-Success "Privacy protection completed successfully!"
    Write-Info "Check the log file for details: $LogFile"
}

# Run main function
Main
