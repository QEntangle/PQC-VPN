# PQC-VPN Hub Installation Script for Windows
# Run as Administrator

param(
    [string]$HubIP = "",
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

Write-Info "Starting PQC-VPN Hub installation for Windows..."

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
$baseDir = "C:\PQC-VPN"
$certDir = "$baseDir\certs"
$configDir = "$baseDir\configs"
$logDir = "$baseDir\logs"

@($baseDir, $certDir, "$certDir\ca", "$certDir\hub", "$certDir\spokes", $configDir, $logDir) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Info "Created directory: $_"
    }
}

# Get Hub IP if not provided
if (!$HubIP) {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback|TAP|VPN" }
    $primaryAdapter = $adapters | Select-Object -First 1
    $HubIP = (Get-NetIPAddress -InterfaceAlias $primaryAdapter.Name -AddressFamily IPv4).IPAddress
    
    Write-Info "Auto-detected Hub IP: $HubIP"
    $confirm = Read-Host "Use this IP? (y/n)"
    if ($confirm -ne "y") {
        $HubIP = Read-Host "Enter Hub IP address"
    }
}

Write-Info "Using Hub IP: $HubIP"

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
    gettext flex bison autoconf automake libtool git wget python3 python3-pip

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

# Configure Windows networking
if (!$SkipFirewall) {
    Write-Info "Configuring Windows Firewall..."
    
    # Allow strongSwan ports
    New-NetFirewallRule -DisplayName "strongSwan IKE" -Direction Inbound -Protocol UDP -LocalPort 500 -Action Allow -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "strongSwan NAT-T" -Direction Inbound -Protocol UDP -LocalPort 4500 -Action Allow -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "strongSwan ESP" -Direction Inbound -Protocol 50 -Action Allow -ErrorAction SilentlyContinue
    
    Write-Success "Firewall rules configured."
}

# Generate PQC certificates
Write-Info "Generating PQC certificates..."
$certScript = @"
#!/bin/bash
set -e

cd /mnt/c/PQC-VPN

# Generate CA private key and certificate using Dilithium
openssl genpkey -algorithm dilithium5 -out certs/ca/ca-key.pem
openssl req -new -x509 -key certs/ca/ca-key.pem -sha256 -days 3650 -out certs/ca/ca-cert.pem \
    -subj "/C=US/ST=CA/L=SF/O=PQC-VPN/OU=CA/CN=PQC-VPN-CA"

# Generate Hub private key and certificate
openssl genpkey -algorithm dilithium5 -out certs/hub/hub-key.pem
openssl req -new -key certs/hub/hub-key.pem -out certs/hub/hub.csr \
    -subj "/C=US/ST=CA/L=SF/O=PQC-VPN/OU=Hub/CN=$HubIP"
openssl x509 -req -in certs/hub/hub.csr -CA certs/ca/ca-cert.pem -CAkey certs/ca/ca-key.pem \
    -CAcreateserial -out certs/hub/hub-cert.pem -days 365 -sha256

echo "PQC certificates generated successfully."
"@

$certScript -replace '\$HubIP', $HubIP | wsl -d Ubuntu bash

Write-Success "PQC certificates generated."

# Copy configuration files to WSL2
Write-Info "Configuring strongSwan..."
wsl -d Ubuntu cp /mnt/c/PQC-VPN/configs/hub/* /etc/

# Update configuration with actual Hub IP
$ipsecConf = Get-Content "$PSScriptRoot\..\configs\hub\ipsec.conf" -Raw
$ipsecConf = $ipsecConf -replace '%HUB_IP%', $HubIP
$ipsecConf | wsl -d Ubuntu tee /etc/ipsec.conf > $null

Write-Success "strongSwan configured."

# Create Windows service to manage WSL2 strongSwan
$serviceName = "PQC-VPN-Hub"
$serviceScript = @"
@echo off
wsl -d Ubuntu sudo ipsec start --nofork
"@

$serviceScript | Out-File -FilePath "$baseDir\start-hub.bat" -Encoding ASCII

# Install as Windows service
if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service $serviceName -Force
    sc.exe delete $serviceName
}

sc.exe create $serviceName binpath= "$baseDir\start-hub.bat" start= auto
sc.exe description $serviceName "PQC-VPN Hub Service"

Write-Success "Windows service created."

# Start the service
Write-Info "Starting PQC-VPN Hub service..."
wsl -d Ubuntu sudo ipsec start
Start-Service $serviceName

Write-Success "PQC-VPN Hub service started."

# Create management scripts
$managementScript = @"
# PQC-VPN Hub Management Script
param([string]$Action)

switch ($Action) {
    "start" { 
        Start-Service PQC-VPN-Hub 
        Write-Host "Hub started."
    }
    "stop" { 
        Stop-Service PQC-VPN-Hub 
        Write-Host "Hub stopped."
    }
    "restart" { 
        Restart-Service PQC-VPN-Hub 
        Write-Host "Hub restarted."
    }
    "status" { 
        wsl -d Ubuntu sudo ipsec status
    }
    "logs" { 
        wsl -d Ubuntu sudo journalctl -u strongswan -f
    }
    default { 
        Write-Host "Usage: .\manage-hub.ps1 [start|stop|restart|status|logs]"
    }
}
"@

$managementScript | Out-File -FilePath "$baseDir\manage-hub.ps1" -Encoding UTF8

Write-Success "Management script created: $baseDir\manage-hub.ps1"

# Final instructions
Write-Info "Installation completed successfully!"
Write-Info ""
Write-Info "Next steps:"
Write-Info "1. Install spoke clients using install-spoke-windows.ps1"
Write-Info "2. Use manage-hub.ps1 to control the hub service"
Write-Info "3. Check logs with: .\manage-hub.ps1 logs"
Write-Info "4. Hub IP: $HubIP"
Write-Info "5. Certificates located in: $certDir"
Write-Info ""
Write-Success "PQC-VPN Hub is ready!"

Read-Host "Press Enter to exit..."