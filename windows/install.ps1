function Test-Administrator {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Start-Installer () {
    # Navigate to the script's directory
    cd $PSScriptRoot
    
    # Clone the repository
    try {
        Invoke-WebRequest -Uri https://github.com/svobodaland/xray-client/archive/refs/heads/master.zip -OutFile master.zip -ErrorAction Stop 
        Expand-Archive master.zip -DestinationPath . -ErrorAction Stop
        rm master.zip
    } catch {
        Write-Error "[x] Failed to download and extract the client"
        exit 1
    }

    # Copy config into client's directory
    if (-not (Test-Path "config.json")) {
        echo "[!] There is no config.json in the current directory"
    } else {
        cp config.json xray-client-master/windows
    }

    # Navigate to the client's directory
    cd xray-client-master/windows

    if (-not (Test-Path "config.json")) {
        Write-Host "[?] Put config.json in the current directory and run '.\run.ps1'"
        exit
    }

    .\run.ps1
}

if (Test-Administrator) {
    Start-Installer
}
else {
    Write-Host "[!] This script requires administrator privileges."
    Start-Process -FilePath "powershell" -ArgumentList "$('-File ""')$(Get-Location)$('\')$($MyInvocation.MyCommand.Name)$('""')" -Verb runAs
}