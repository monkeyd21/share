# ======================================================================
# KiteCyber ReInstaller Script
# ======================================================================

# Step 0: Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please re-run with elevated privileges." -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit 1
}

# Step 1: Check for existing downloads
$kc_folder = "C:\Program Files (x86)\Kitecyber\Clientagent"

if (Test-Path $kc_folder) {
   Write-Host "$kc_folder exists"
} else {
    Write-Host "$kc_folder does not exist. Exiting." -ForegroundColor Red
    exit 1
}

# Step 2: Fetch the JSON response using Invoke-RestMethod (defensive)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $jsonResponse = Invoke-RestMethod -Uri 'https://api-in.kitecyber.com/agent-download?p=WINDOWS_AMD_64_NA&t=INSTALL' -Headers @{ 'Accept' = 'application/json' } -ErrorAction Stop
    Write-Host "Successfully fetched API response." -ForegroundColor Green
} catch {
    Write-Host "Failed to fetch API response: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.InnerException) {
        Write-Host "Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor DarkGray
    }
    Test-NetConnection api-in.kitecyber.com -Port 443 | Format-List
    exit 1
}

# Step 3: Parse JSON to extract download URL and filename
$downloadUrl = $jsonResponse.download_url
# Clear downloads directory if it exists
$downloadsDir = "C:\Users\Public\Downloads"
if (Test-Path $downloadsDir) {
    try {
        Remove-Item -Path "$downloadsDir\*" -Force -Recurse -ErrorAction Stop
        Write-Host "Cleared downloads directory." -ForegroundColor Green
    } catch {
        Write-Host "Warning: Could not clear downloads directory: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    New-Item -ItemType Directory -Path $downloadsDir -Force | Out-Null
}
$fileName = [System.IO.Path]::Combine("C:\Users\Public\Downloads", $jsonResponse.file_name)
Write-Host "Downloading file from: $downloadUrl" -ForegroundColor Cyan
Write-Host "Saving as: $fileName" -ForegroundColor Gray

# Step 4: Download the file
try {
    Write-Host "Downloading Kitecyber Copilot" -ForegroundColor Yellow
    Invoke-WebRequest -Uri $downloadUrl -OutFile $fileName -UseBasicParsing -ErrorAction Stop
    Write-Host "File downloaded successfully." -ForegroundColor Green
} catch {
    Write-Host ("Download failed" + $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# Step 5: Reset Proxy
try {
    # Get the currently logged-in user's SID
    $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    if ($loggedInUser -match '\\') {
        $username = $loggedInUser.Split('\')[1]
        $domain = $loggedInUser.Split('\')[0]
    } else {
        $username = $loggedInUser
    }
    
    # Get the user's SID
    $userSID = (New-Object System.Security.Principal.NTAccount($loggedInUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    
    # Target the user's registry hive
    $userProxyPath = "Registry::HKEY_USERS\$userSID\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    # Clear proxy settings
    $proxySettings = Get-ItemProperty -Path $userProxyPath -ErrorAction SilentlyContinue
    if ($proxySettings) {
        Set-ItemProperty -Path $userProxyPath -Name ProxyEnable -Value 0
        
        # Optionally clear the proxy server value too
        if ($proxySettings.ProxyServer) {
            Remove-ItemProperty -Path $userProxyPath -Name ProxyServer -ErrorAction SilentlyContinue
        }
        
        Write-Host "Proxy settings cleared for user: $loggedInUser" -ForegroundColor Green
    } else {
        Write-Host "No proxy settings found for user: $loggedInUser" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Failed to reset proxy settings: $($_.Exception.Message)" -ForegroundColor Red
}


# Step 6: Kill running processes

$serviceName = "kitecyber_service"
$maxRetries = 5
$retryCount = 0
$serviceStopped = $false

Write-Output "Checking service: $serviceName"

while ($retryCount -lt $maxRetries) {
    # Stop the service
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds 5

    # Kill the tray process if it exists
    $trayProcess = Get-Process "kitecyber-tray" -ErrorAction SilentlyContinue
    if ($trayProcess) {
        Stop-Process -Name "kitecyber-tray" -Force -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 5

    # Check if service is actually stopped
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc -eq $null -or $svc.Status -ne 'Running') {
        $serviceStopped = $true
        break
    }

    $retryCount++
    Write-Output "Attempt $retryCount of $($maxRetries): Failed to stop service $serviceName. Retrying..."
}

if (-not $serviceStopped) {
    Write-Error "Failed to stop service $serviceName after $maxRetries attempts"
    exit 1
}

Stop-Process -Name "KitecyberAutostarterService" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "clientagent" -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 1000

$processNames = @("KitecyberAutostarterService", "clientagent")
foreach ($processName in $processNames) {
    $processCheck = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($processCheck) {
        Write-Output "Process $processName is still running. Force stopping it."
        Stop-Process -Name $processName -Force
    } else {
        Write-Output "Process $processName is not running."
    }
}

# Step 7: Uninstall previous version if present
$INSTDIR = "C:\Program Files (x86)\Kitecyber\Clientagent"
$exePath = Join-Path -Path $INSTDIR -ChildPath "KitecyberUninstall.exe"

if (Test-Path $exePath) {
    try {
        Start-Process -FilePath $exePath -ArgumentList "/S" -Wait -Verb RunAs
        Write-Host "Previous version uninstalled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to run uninstaller: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Uninstaller not found: $exePath" -ForegroundColor DarkGray
}

# Step 8: Remove registry key
$regPath = "HKCU:\SOFTWARE\KiteCyber\ClientAgent"
if (Test-Path $regPath) {
    try {
        Remove-Item -Path $regPath -Recurse -Force
        Write-Host "Removed registry key: $regPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove registry key $regPath : $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Registry key not found: $regPath" -ForegroundColor DarkGray
}

# Step 9: Verify downloaded file
if (-not (Test-Path $fileName)) {
    Write-Host "Could not find downloaded file: $fileName" -ForegroundColor Red
    exit 1
}

# Step 10: Execute installer
try {
    Write-Host "Running installer in background..." -ForegroundColor Cyan
    $process = Start-Process -FilePath $fileName -Verb RunAs -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 30
    Write-Host "Installer started with PID: $($process.Id)" -ForegroundColor Gray
} catch {
    Write-Host "Failed to start installer: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 11: Check installation directory
if (Test-Path $INSTDIR) {
    $files = Get-ChildItem -Path $INSTDIR -File -ErrorAction SilentlyContinue
    if ($files.Count -gt 0) {
        Write-Host "Installation directory found with files." -ForegroundColor Green
    } else {
        Write-Host "Installation directory exists but is empty." -ForegroundColor Yellow
    }
} else {
    Write-Host "Installation directory not found: $INSTDIR" -ForegroundColor Red
}
