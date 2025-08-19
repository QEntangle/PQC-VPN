# PQC-VPN Spoke Installation Script for Windows
# Run as Administrator

param(
    [string]$HubIP = "",
    [string]$SpokeUser = "",
    [switch]$SkipFirewall = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Info($message) {
    Write-ColorOutput Green "ℹ️  $message"
}

function Write-Warning($message) {
    Write-ColorOutput Yellow "⚠️  $message"
}

function Write-Error($message) {
    Write-ColorOutput Red "❌ $message"
}

function Write-Success($message) {
    Write-ColorOutput Green "✅ $message"
}

Write-Info "Starting PQC-VPN Spoke installation for Windows..."

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Please restart PowerShell as Administrator."
    exit 1
}

# Check Windows version
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Write-Error "Windows 10 or higher is required."
    exit 1
}

Write-Success "Administrator privileges confirmed."

# Get parameters if not provided
if (!$HubIP) {
    $HubIP = Read-Host "Enter Hub IP address"
}

if (!$SpokeUser) {
    $SpokeUser = Read-Host "Enter spoke username"
}

if (!$HubIP -or !$SpokeUser) {
    Write-Error "Hub IP and spoke username are required."
    exit 1
}

Write-Info "Hub IP: $HubIP"
Write-Info "Spoke User: $SpokeUser"

# Install Chocolatey if not present
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Info "Installing Chocolatey package manager..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Success "Chocolatey installed."
}

# Install WSL2 and Ubuntu if not present
Write-Info "Checking WSL2 installation..."
$wslStatus = wsl --status 2>$null
if (!$wslStatus) {
    Write-Info "Installing WSL2..."
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
    
    Write-Warning "WSL2 requires a reboot. Please reboot and run this script again."
    Read-Host "Press Enter to exit..."
    exit 0
}

# Install Ubuntu if not present
if (!(wsl -l -v | Select-String "Ubuntu")) {
    Write-Info "Installing Ubuntu for WSL2..."
    wsl --install -d Ubuntu
    Write-Info "Please complete Ubuntu setup and run this script again."
    Read-Host "Press Enter to exit..."
    exit 0
}

Write-Success "WSL2 and Ubuntu are available."

# Install required tools
Write-Info "Installing required tools..."
choco install -y git curl wget openssh 7zip

# Create directories
$baseDir = "C:\PQC-VPN-Spoke"
$certDir = "$baseDir\certs"
$configDir = "$baseDir\configs"
$logDir = "$baseDir\logs"
$scriptsDir = "$baseDir\scripts"

@($baseDir, $certDir, $configDir, $logDir, $scriptsDir) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Info "Created directory: $_"
    }
}

# Install strongSwan in WSL2
Write-Info "Installing strongSwan in WSL2..."
$wslCommands = @"
#!/bin/bash
set -e

echo "Updating package list..."
sudo apt update

echo "Installing dependencies..."
sudo apt install -y build-essential libssl-dev libgmp-dev libtspi-dev libldap2-dev \
    libcurl4-openssl-dev libxml2-dev libsystemd-dev libpcsclite-dev pkg-config \
    gettext flex bison autoconf automake libtool git wget python3 python3-pip cmake ninja-build

echo "Installing liboqs for PQC support..."
cd /tmp
git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
sudo ldconfig

echo "Installing strongSwan with PQC support..."
cd /tmp
git clone https://github.com/strongswan/strongswan.git
cd strongswan
git checkout 5.9.14
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --enable-openssl --enable-python-eggs \
    --enable-cmd --enable-conf --enable-connmark --enable-dhcp --enable-eap-aka \
    --enable-eap-gtc --enable-eap-identity --enable-eap-md5 --enable-eap-mschapv2 \
    --enable-eap-radius --enable-eap-tls --enable-farp --enable-files --enable-gcrypt \
    --enable-gmp --enable-ldap --enable-mysql --enable-sqlite --enable-stroke \
    --enable-updown --enable-unity --enable-xauth-eap --enable-xauth-pam \
    --enable-chapoly --enable-curl --enable-systemd --disable-des --enable-oqs
make -j\$(nproc)
sudo make install
sudo systemctl daemon-reload

echo "strongSwan installation completed."
"@

$wslCommands | wsl -d Ubuntu bash

Write-Success "strongSwan with PQC support installed in WSL2."

# Generate PQC certificates
Write-Info "Generating PQC certificates for spoke: $SpokeUser"
$certScript = @"
#!/bin/bash
set -e

cd /mnt/c/PQC-VPN-Spoke

# Create certificate directory structure
mkdir -p certs

# Generate spoke private key using Dilithium
openssl genpkey -algorithm dilithium5 -out certs/${SpokeUser}-key.pem

# Generate certificate request
openssl req -new -key certs/${SpokeUser}-key.pem -out certs/${SpokeUser}.csr \
    -subj "/C=US/ST=CA/L=SF/O=PQC-VPN/OU=Spoke/CN=${SpokeUser}"

echo "Certificate request generated: ${SpokeUser}.csr"
echo "Please send this file to the hub administrator to get it signed."
"@

$certScript -replace '\${SpokeUser}', $SpokeUser | wsl -d Ubuntu bash

Write-Success "PQC certificate request generated for $SpokeUser."

# Configure strongSwan in WSL2
Write-Info "Configuring strongSwan..."
$configScript = @"
#!/bin/bash
set -e

# Copy spoke configuration template and customize
sed -e "s/%HUB_IP%/${HubIP}/g" \
    -e "s/%SPOKE_USER%/${SpokeUser}/g" \
    /mnt/c/PQC-VPN-Spoke/configs/spoke/ipsec.conf.template > /etc/ipsec.conf

# Copy spoke secrets template and customize
sed -e "s/%SPOKE_USER%/${SpokeUser}/g" \
    /mnt/c/PQC-VPN-Spoke/configs/spoke/ipsec.secrets.template > /etc/ipsec.secrets

# Copy strongswan configuration
cp /mnt/c/PQC-VPN-Spoke/configs/spoke/strongswan.conf /etc/strongswan.conf

# Set proper permissions
chmod 600 /etc/ipsec.secrets

# Create ipsec.d directories
mkdir -p /etc/ipsec.d/{cacerts,certs,private}

echo "strongSwan configuration completed."
"@

# Copy config files to Windows first
Copy-Item "$PSScriptRoot\..\configs\spoke\*" -Destination "$configDir\" -Recurse -Force

$configScript -replace '\${HubIP}', $HubIP -replace '\${SpokeUser}', $SpokeUser | wsl -d Ubuntu bash

Write-Success "strongSwan configured."

# Configure Windows networking
if (!$SkipFirewall) {
    Write-Info "Configuring Windows Firewall..."
    
    # Allow strongSwan ports
    New-NetFirewallRule -DisplayName "strongSwan IKE" -Direction Outbound -Protocol UDP -LocalPort 500 -Action Allow -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "strongSwan NAT-T" -Direction Outbound -Protocol UDP -LocalPort 4500 -Action Allow -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "strongSwan ESP" -Direction Outbound -Protocol 50 -Action Allow -ErrorAction SilentlyContinue
    
    Write-Success "Firewall rules configured."
}

# Create management scripts
Write-Info "Creating management scripts..."

# Connect script
$connectScript = @"
@echo off
echo Connecting to PQC-VPN Hub...
wsl -d Ubuntu sudo ipsec start
wsl -d Ubuntu sudo ipsec up pqc-vpn
echo Connection status:
wsl -d Ubuntu sudo ipsec status
"@

$connectScript | Out-File -FilePath "$scriptsDir\connect.bat" -Encoding ASCII

# Disconnect script
$disconnectScript = @"
@echo off
echo Disconnecting from PQC-VPN Hub...
wsl -d Ubuntu sudo ipsec down pqc-vpn
wsl -d Ubuntu sudo ipsec stop
echo Disconnected.
"@

$disconnectScript | Out-File -FilePath "$scriptsDir\disconnect.bat" -Encoding ASCII

# Status script
$statusScript = @"
@echo off
echo PQC-VPN Status:
echo ===============
wsl -d Ubuntu sudo ipsec status
echo.
echo Active tunnels:
wsl -d Ubuntu ip route show table 220 2>nul || echo No active tunnels
"@

$statusScript | Out-File -FilePath "$scriptsDir\status.bat" -Encoding ASCII

# Certificate installation script
$certInstallScript = @"
@echo off
if "%~1"=="" goto usage
if "%~2"=="" goto usage

set SPOKE_CERT=%~1
set CA_CERT=%~2

if not exist "%SPOKE_CERT%" (
    echo Certificate file not found: %SPOKE_CERT%
    exit /b 1
)

if not exist "%CA_CERT%" (
    echo CA certificate file not found: %CA_CERT%
    exit /b 1
)

echo Installing certificates...
wsl -d Ubuntu sudo cp "/mnt/c/%SPOKE_CERT%" /etc/ipsec.d/certs/
wsl -d Ubuntu sudo cp "/mnt/c/%CA_CERT%" /etc/ipsec.d/cacerts/

echo Certificates installed successfully
echo You can now connect using: %~dp0connect.bat
goto end

:usage
echo Usage: %~nx0 ^<spoke-cert.pem^> ^<ca-cert.pem^>
echo Example: %~nx0 alice-cert.pem ca-cert.pem
echo.
echo Make sure certificate files are in Windows filesystem (C:\)

:end
"@

$certInstallScript | Out-File -FilePath "$scriptsDir\install-certs.bat" -Encoding ASCII

# PowerShell management script
$psManagementScript = @"
# PQC-VPN Spoke Management Script
param([string]$Action)

switch ($Action) {
    "connect" { 
        Write-Host "Connecting to PQC-VPN Hub..."
        wsl -d Ubuntu sudo ipsec start
        wsl -d Ubuntu sudo ipsec up pqc-vpn
        Write-Host "Connected. Checking status..."
        wsl -d Ubuntu sudo ipsec status
    }
    "disconnect" { 
        Write-Host "Disconnecting from PQC-VPN Hub..."
        wsl -d Ubuntu sudo ipsec down pqc-vpn
        wsl -d Ubuntu sudo ipsec stop
        Write-Host "Disconnected."
    }
    "status" { 
        Write-Host "PQC-VPN Status:"
        Write-Host "==============="
        wsl -d Ubuntu sudo ipsec status
        Write-Host ""
        Write-Host "Active tunnels:"
        wsl -d Ubuntu ip route show table 220 2>`$null
        if (!`$?) { Write-Host "No active tunnels" }
    }
    "logs" { 
        Write-Host "Recent logs:"
        wsl -d Ubuntu sudo journalctl -u strongswan -n 50 --no-pager
    }
    default { 
        Write-Host "Usage: .\manage-spoke.ps1 [connect|disconnect|status|logs]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  connect     - Connect to PQC-VPN hub"
        Write-Host "  disconnect  - Disconnect from PQC-VPN hub"  
        Write-Host "  status      - Show connection status"
        Write-Host "  logs        - Show recent logs"
    }
}
"@

$psManagementScript | Out-File -FilePath "$scriptsDir\manage-spoke.ps1" -Encoding UTF8

Write-Success "Management scripts created."

# Create desktop shortcuts
Write-Info "Creating desktop shortcuts..."

$desktopPath = [Environment]::GetFolderPath("Desktop")

# Connect shortcut
$connectShortcut = @"
[InternetShortcut]
URL=file:///$($scriptsDir.Replace('\', '/'))/connect.bat
IconIndex=0
"@

$connectShortcut | Out-File -FilePath "$desktopPath\PQC-VPN Connect.url" -Encoding ASCII

# Disconnect shortcut
$disconnectShortcut = @"
[InternetShortcut] 
URL=file:///$($scriptsDir.Replace('\', '/'))/disconnect.bat
IconIndex=0
"@

$disconnectShortcut | Out-File -FilePath "$desktopPath\PQC-VPN Disconnect.url" -Encoding ASCII

Write-Success "Desktop shortcuts created."

# Final instructions
Write-Info "Installation completed successfully!"
Write-Info ""
Write-Info "Certificate Request Generated:"
Write-Info "  Location: $certDir\$SpokeUser.csr"
Write-Info "  Hub IP: $HubIP"
Write-Info "  Spoke User: $SpokeUser"
Write-Info ""
Write-Info "Next steps:"
Write-Info "1. Send certificate request to hub administrator:"
Write-Info "   File: $certDir\$SpokeUser.csr"
Write-Info ""
Write-Info "2. Get signed certificate and CA certificate from hub admin"
Write-Info ""
Write-Info "3. Install certificates using:"
Write-Info "   $scriptsDir\install-certs.bat <your-cert.pem> <ca-cert.pem>"
Write-Info ""
Write-Info "4. Connect to VPN:"
Write-Info "   - Use desktop shortcut 'PQC-VPN Connect'"
Write-Info "   - Or run: $scriptsDir\connect.bat"
Write-Info "   - Or use PowerShell: $scriptsDir\manage-spoke.ps1 connect"
Write-Info ""
Write-Info "5. Management commands:"
Write-Info "   - Status: $scriptsDir\manage-spoke.ps1 status"
Write-Info "   - Disconnect: $scriptsDir\manage-spoke.ps1 disconnect"
Write-Info "   - Logs: $scriptsDir\manage-spoke.ps1 logs"
Write-Info ""
Write-Success "PQC-VPN Spoke is ready for certificate installation!"

Read-Host "Press Enter to exit..."