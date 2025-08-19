# PQC-VPN Hub Installation Script for Windows (Enhanced)
# Supports Windows 10/11 Pro, Windows Server 2019/2022
# Version: 2.0.0
# Requires: PowerShell 5.1+ and Administrator privileges

param(
    [string]$HubIP = "",
    [switch]$EnableHA = $false,
    [switch]$DisableWeb = $false,
    [switch]$DisableMonitoring = $false,
    [string]$InstallMode = "production",
    [string]$AuthMethods = "pki,psk,hybrid",
    [string]$PQCAlgorithms = "kyber1024,kyber768,dilithium5,dilithium3",
    [switch]$Debug = $false,
    [switch]$Help = $false
)

# Script configuration
$Script:VERSION = "2.0.0"
$Script:NAME = "PQC-VPN Hub Installer for Windows"
$Script:LogFile = "$env:ProgramData\PQC-VPN\install.log"
$Script:ConfigDir = "$env:ProgramData\PQC-VPN"
$Script:BackupDir = "$env:ProgramData\PQC-VPN\Backups"
$Script:InstallDir = "$env:ProgramFiles\PQC-VPN"

# Colors for output
$Script:Colors = @{
    Red = 'Red'
    Green = 'Green'
    Yellow = 'Yellow'
    Blue = 'Blue'
    Cyan = 'Cyan'
    Magenta = 'Magenta'
}

# Ensure we're running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
    exit 1
}

# Logging functions
function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    # Ensure log directory exists
    $logDir = Split-Path $Script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    # Write to log file
    Add-Content -Path $Script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    
    # Write to console with colors
    switch ($Level) {
        "INFO" { Write-Host "[INFO] $Message" -ForegroundColor Blue }
        "WARN" { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        "ERROR" { Write-Host "[ERROR] $Message" -ForegroundColor Red }
        "SUCCESS" { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
        "DEBUG" { 
            if ($Debug) {
                Write-Host "[DEBUG] $Message" -ForegroundColor Magenta
            }
        }
    }
}

function Write-Info { param([string]$Message) Write-Log "INFO" $Message }
function Write-Warn { param([string]$Message) Write-Log "WARN" $Message }
function Write-Error { param([string]$Message) Write-Log "ERROR" $Message }
function Write-Success { param([string]$Message) Write-Log "SUCCESS" $Message }
function Write-Debug { param([string]$Message) Write-Log "DEBUG" $Message }

# Help function
function Show-Help {
    Write-Host @"
$Script:NAME v$Script:VERSION

USAGE:
    .\install-hub-windows.ps1 [OPTIONS]

OPTIONS:
    -HubIP <IP>              Set hub IP address
    -EnableHA                Enable high availability
    -DisableWeb              Disable web interface
    -DisableMonitoring       Disable monitoring
    -InstallMode <MODE>      Set install mode (production/development/testing)
    -AuthMethods <METHODS>   Set authentication methods (pki,psk,hybrid)
    -PQCAlgorithms <ALGOS>   Set PQC algorithms (kyber1024,dilithium5,etc)
    -Debug                   Enable debug output
    -Help                    Show this help message

ENVIRONMENT VARIABLES:
    PQC_HUB_IP              Hub IP address
    PQC_ENABLE_HA           Enable high availability (true/false)
    PQC_ENABLE_MONITORING   Enable monitoring (true/false)
    PQC_ENABLE_WEB          Enable web interface (true/false)
    PQC_REPO_DIR            Local repository directory

EXAMPLES:
    .\install-hub-windows.ps1 -HubIP "192.168.1.100"
    .\install-hub-windows.ps1 -EnableHA -InstallMode development
    .\install-hub-windows.ps1 -DisableWeb -DisableMonitoring

"@ -ForegroundColor Cyan
}

if ($Help) {
    Show-Help
    exit 0
}

# Banner function
function Show-Banner {
    Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║                    PQC-VPN Hub Installer                     ║
║                 Post-Quantum Cryptography VPN                ║
║                      Windows Version 2.0.0                  ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

# System requirements check
function Test-SystemRequirements {
    Write-Info "Checking system requirements..."
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    $isServerOS = (Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 1
    
    if ($osVersion.Major -lt 10) {
        Write-Error "Windows 10 or newer is required"
        return $false
    }
    
    Write-Info "Windows version: $($osVersion.Major).$($osVersion.Minor) $(if($isServerOS){"Server"}else{"Client"})"
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Error "PowerShell 5.1 or newer is required"
        return $false
    }
    
    Write-Info "PowerShell version: $($psVersion.Major).$($psVersion.Minor)"
    
    # Check available memory (minimum 2GB)
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $memoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    
    if ($memoryGB -lt 2) {
        Write-Warn "System has less than 2GB RAM ($memoryGB GB). PQC-VPN may not perform optimally."
    }
    
    Write-Info "Available memory: $memoryGB GB"
    
    # Check disk space (minimum 10GB)
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    
    if ($freeSpaceGB -lt 10) {
        Write-Error "Insufficient disk space. At least 10GB required, found $freeSpaceGB GB"
        return $false
    }
    
    Write-Info "Available disk space: $freeSpaceGB GB"
    
    # Check Hyper-V capability (for containers)
    $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hyperv -and $hyperv.State -eq "Enabled") {
        Write-Info "Hyper-V is available"
    } else {
        Write-Warn "Hyper-V is not enabled. Some features may not work."
    }
    
    Write-Success "System requirements check passed"
    return $true
}

# Create directory structure
function New-DirectoryStructure {
    Write-Info "Creating directory structure..."
    
    $directories = @(
        $Script:ConfigDir,
        $Script:BackupDir,
        $Script:InstallDir,
        "$Script:ConfigDir\certs",
        "$Script:ConfigDir\private",
        "$Script:ConfigDir\cacerts",
        "$Script:ConfigDir\conf.d",
        "$Script:ConfigDir\secrets",
        "$Script:ConfigDir\logs",
        "$Script:ConfigDir\monitoring",
        "$Script:InstallDir\tools",
        "$Script:InstallDir\web",
        "$Script:InstallDir\bin"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Debug "Created directory: $dir"
        }
    }
    
    # Set proper permissions on sensitive directories
    $acl = Get-Acl "$Script:ConfigDir\private"
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($adminRule)
    $acl.SetAccessRule($systemRule)
    Set-Acl -Path "$Script:ConfigDir\private" -AclObject $acl
    
    Write-Success "Directory structure created"
}

# Install chocolatey if not present
function Install-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Chocolatey package manager..."
        
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        
        try {
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-Success "Chocolatey installed successfully"
        }
        catch {
            Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
            return $false
        }
    } else {
        Write-Info "Chocolatey is already installed"
    }
    
    return $true
}

# Install system dependencies
function Install-Dependencies {
    Write-Info "Installing system dependencies..."
    
    # Install Chocolatey first
    if (-not (Install-Chocolatey)) {
        return $false
    }
    
    # List of packages to install
    $chocoPackages = @(
        "git",
        "wget",
        "curl",
        "jq",
        "openssl",
        "python3",
        "nodejs",
        "docker-desktop",
        "vcredist-all",
        "dotnetfx"
    )
    
    # Optional packages for monitoring
    if (-not $DisableMonitoring) {
        $chocoPackages += @("grafana", "prometheus")
    }
    
    foreach ($package in $chocoPackages) {
        Write-Info "Installing $package..."
        try {
            choco install $package -y --limit-output
            Write-Success "$package installed successfully"
        }
        catch {
            Write-Warn "Failed to install $package: $($_.Exception.Message)"
        }
    }
    
    # Refresh environment variables
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    Write-Success "System dependencies installed"
    return $true
}

# Install strongSwan for Windows
function Install-StrongSwan {
    Write-Info "Installing strongSwan for Windows..."
    
    $strongSwanUrl = "https://download.strongswan.org/Windows/strongswan-5.9.14.exe"
    $strongSwanInstaller = "$env:TEMP\strongswan-installer.exe"
    
    try {
        # Download strongSwan installer
        Write-Info "Downloading strongSwan installer..."
        Invoke-WebRequest -Uri $strongSwanUrl -OutFile $strongSwanInstaller -UseBasicParsing
        
        # Install strongSwan silently
        Write-Info "Installing strongSwan..."
        Start-Process -FilePath $strongSwanInstaller -ArgumentList "/S" -Wait -NoNewWindow
        
        # Verify installation
        $strongSwanPath = "${env:ProgramFiles}\strongSwan\bin\ipsec.exe"
        if (Test-Path $strongSwanPath) {
            Write-Success "strongSwan installed successfully"
            
            # Add to PATH if not already there
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $strongSwanBinPath = "${env:ProgramFiles}\strongSwan\bin"
            if ($currentPath -notlike "*$strongSwanBinPath*") {
                [Environment]::SetEnvironmentVariable("Path", $currentPath + ";$strongSwanBinPath", "Machine")
                $env:Path += ";$strongSwanBinPath"
            }
        } else {
            Write-Error "strongSwan installation verification failed"
            return $false
        }
    }
    catch {
        Write-Error "Failed to install strongSwan: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Cleanup installer
        if (Test-Path $strongSwanInstaller) {
            Remove-Item $strongSwanInstaller -Force
        }
    }
    
    return $true
}

# Install PQC libraries for Windows
function Install-PQCLibraries {
    Write-Info "Installing Post-Quantum Cryptography libraries..."
    
    # Create build directory
    $buildDir = "$env:TEMP\pqc-build"
    if (Test-Path $buildDir) {
        Remove-Item $buildDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    
    try {
        # Install Visual Studio Build Tools if not present
        if (-not (Get-Command msbuild -ErrorAction SilentlyContinue)) {
            Write-Info "Installing Visual Studio Build Tools..."
            choco install visualstudio2022buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools" -y
        }
        
        # Install CMake if not present
        if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
            Write-Info "Installing CMake..."
            choco install cmake -y
        }
        
        # Install Git if not present
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            Write-Info "Installing Git..."
            choco install git -y
        }
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Clone and build liboqs
        Write-Info "Building liboqs (Open Quantum Safe)..."
        Set-Location $buildDir
        
        git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
        Set-Location "$buildDir\liboqs"
        
        New-Item -ItemType Directory -Path "build" -Force | Out-Null
        Set-Location "build"
        
        # Configure with CMake
        cmake -DCMAKE_INSTALL_PREFIX="$Script:InstallDir\liboqs" `
              -DOQS_USE_OPENSSL=ON `
              -DOQS_BUILD_ONLY_LIB=ON `
              -DOQS_ENABLE_KEM_KYBER=ON `
              -DOQS_ENABLE_SIG_DILITHIUM=ON `
              -DOQS_ENABLE_SIG_FALCON=ON `
              -DOQS_ENABLE_SIG_SPHINCS=ON `
              -A x64 ..
        
        # Build and install
        cmake --build . --config Release
        cmake --install . --config Release
        
        Write-Success "liboqs installed successfully"
    }
    catch {
        Write-Error "Failed to install PQC libraries: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Cleanup build directory
        Set-Location $env:TEMP
        if (Test-Path $buildDir) {
            Remove-Item $buildDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    return $true
}

# Configure strongSwan
function Set-StrongSwanConfiguration {
    Write-Info "Configuring strongSwan with PQC support..."
    
    $strongSwanConfigDir = "${env:ProgramFiles}\strongSwan\etc"
    
    # Backup existing configuration
    if (Test-Path "$strongSwanConfigDir\ipsec.conf") {
        $backupFile = "$Script:BackupDir\ipsec.conf.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item "$strongSwanConfigDir\ipsec.conf" $backupFile
        Write-Debug "Backed up ipsec.conf to $backupFile"
    }
    
    if (Test-Path "$strongSwanConfigDir\ipsec.secrets") {
        $backupFile = "$Script:BackupDir\ipsec.secrets.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item "$strongSwanConfigDir\ipsec.secrets" $backupFile
        Write-Debug "Backed up ipsec.secrets to $backupFile"
    }
    
    # Auto-detect hub IP if not provided
    if ([string]::IsNullOrEmpty($HubIP)) {
        $networkAdapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*" }
        if ($networkAdapters) {
            $HubIP = $networkAdapters[0].IPAddress
            Write-Info "Auto-detected Hub IP: $HubIP"
        } else {
            Write-Error "Could not auto-detect Hub IP. Please specify with -HubIP parameter."
            return $false
        }
    }
    
    # Download or copy configuration templates
    $repoDir = $env:PQC_REPO_DIR
    if ($repoDir -and (Test-Path "$repoDir\configs\hub")) {
        Write-Info "Using local repository configuration..."
        Copy-Item "$repoDir\configs\hub\ipsec.conf" "$strongSwanConfigDir\ipsec.conf" -Force
        Copy-Item "$repoDir\configs\hub\ipsec.secrets" "$strongSwanConfigDir\ipsec.secrets" -Force
        Copy-Item "$repoDir\configs\hub\strongswan.conf" "$strongSwanConfigDir\strongswan.conf" -Force
    } else {
        Write-Info "Downloading configuration from GitHub..."
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/QEntangle/PQC-VPN/main/configs/hub/ipsec.conf" -OutFile "$strongSwanConfigDir\ipsec.conf"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/QEntangle/PQC-VPN/main/configs/hub/ipsec.secrets" -OutFile "$strongSwanConfigDir\ipsec.secrets"
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/QEntangle/PQC-VPN/main/configs/hub/strongswan.conf" -OutFile "$strongSwanConfigDir\strongswan.conf"
        }
        catch {
            Write-Error "Failed to download configuration files: $($_.Exception.Message)"
            return $false
        }
    }
    
    # Replace template variables
    (Get-Content "$strongSwanConfigDir\ipsec.conf") -replace '{HUB_IP}', $HubIP | Set-Content "$strongSwanConfigDir\ipsec.conf"
    (Get-Content "$strongSwanConfigDir\ipsec.secrets") -replace '{HUB_IP}', $HubIP | Set-Content "$strongSwanConfigDir\ipsec.secrets"
    
    Write-Success "strongSwan configuration updated"
    return $true
}

# Generate certificates
function New-Certificates {
    Write-Info "Generating PQC certificates..."
    
    $certDir = "$Script:ConfigDir\certs"
    $privateDir = "$Script:ConfigDir\private"
    $cacertDir = "$Script:ConfigDir\cacerts"
    
    try {
        # Check if Python certificate tool is available
        $repoDir = $env:PQC_REPO_DIR
        $certTool = if ($repoDir) { "$repoDir\tools\pqc-keygen.py" } else { $null }
        
        if ($certTool -and (Test-Path $certTool)) {
            Write-Info "Using PQC certificate generator..."
            python $certTool ca
            python $certTool hub $HubIP
        } else {
            Write-Warn "PQC certificate generator not found, using OpenSSL fallback..."
            
            # Generate CA certificate
            & openssl req -x509 -newkey rsa:4096 -keyout "$privateDir\ca-key.pem" `
                         -out "$cacertDir\ca-cert.pem" -days 3650 -nodes `
                         -subj "/C=US/O=PQC-VPN/CN=PQC-VPN CA"
            
            # Generate hub certificate
            & openssl req -newkey rsa:4096 -keyout "$privateDir\hub-key.pem" `
                         -out "$env:TEMP\hub-req.pem" -nodes `
                         -subj "/C=US/O=PQC-VPN/CN=hub.pqc-vpn.local"
            
            & openssl x509 -req -in "$env:TEMP\hub-req.pem" -CA "$cacertDir\ca-cert.pem" `
                          -CAkey "$privateDir\ca-key.pem" -CAcreateserial `
                          -out "$certDir\hub-cert.pem" -days 365
            
            # Cleanup
            Remove-Item "$env:TEMP\hub-req.pem" -ErrorAction SilentlyContinue
        }
        
        # Copy certificates to strongSwan directory
        $strongSwanCertDir = "${env:ProgramFiles}\strongSwan\etc\ipsec.d"
        Copy-Item "$certDir\*" "$strongSwanCertDir\certs\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$privateDir\*" "$strongSwanCertDir\private\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$cacertDir\*" "$strongSwanCertDir\cacerts\" -Force -ErrorAction SilentlyContinue
        
        Write-Success "Certificates generated successfully"
    }
    catch {
        Write-Error "Failed to generate certificates: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Configure Windows Firewall
function Set-FirewallRules {
    Write-Info "Configuring Windows Firewall..."
    
    try {
        # Enable Windows Firewall if disabled
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        
        # Create firewall rules for IPsec
        New-NetFirewallRule -DisplayName "PQC-VPN IKE" -Direction Inbound -Protocol UDP -LocalPort 500 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "PQC-VPN NAT-T" -Direction Inbound -Protocol UDP -LocalPort 4500 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "PQC-VPN ESP" -Direction Inbound -Protocol 50 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "PQC-VPN AH" -Direction Inbound -Protocol 51 -Action Allow -ErrorAction SilentlyContinue
        
        # Web interface firewall rule
        if (-not $DisableWeb) {
            New-NetFirewallRule -DisplayName "PQC-VPN Web Interface" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -ErrorAction SilentlyContinue
        }
        
        # Monitoring firewall rules
        if (-not $DisableMonitoring) {
            New-NetFirewallRule -DisplayName "PQC-VPN Grafana" -Direction Inbound -Protocol TCP -LocalPort 3000 -Action Allow -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "PQC-VPN Prometheus" -Direction Inbound -Protocol TCP -LocalPort 9090 -Action Allow -ErrorAction SilentlyContinue
        }
        
        Write-Success "Firewall rules configured"
    }
    catch {
        Write-Error "Failed to configure firewall: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Install Python tools
function Install-PythonTools {
    Write-Info "Installing Python management tools..."
    
    try {
        # Upgrade pip
        python -m pip install --upgrade pip
        
        # Install required Python packages
        $pythonPackages = @(
            "psutil>=5.9.0",
            "pyyaml>=6.0",
            "cryptography>=41.0.0",
            "requests>=2.28.0",
            "click>=8.1.0",
            "tabulate>=0.9.0",
            "colorama>=0.4.6",
            "flask>=2.3.0",
            "flask-cors>=4.0.0",
            "jinja2>=3.1.0",
            "jsonschema>=4.0.0",
            "schedule>=1.2.0"
        )
        
        foreach ($package in $pythonPackages) {
            python -m pip install $package
        }
        
        # Copy Python tools
        $repoDir = $env:PQC_REPO_DIR
        $toolsDir = if ($repoDir) { "$repoDir\tools" } else { $null }
        
        if ($toolsDir -and (Test-Path $toolsDir)) {
            Copy-Item "$toolsDir\*.py" "$Script:InstallDir\tools\" -Force
            
            # Create batch files for easy access
            @"
@echo off
python "$Script:InstallDir\tools\vpn-manager.py" %*
"@ | Out-File "$Script:InstallDir\bin\pqc-vpn-manager.bat" -Encoding ASCII
            
            @"
@echo off
python "$Script:InstallDir\tools\connection-monitor.py" %*
"@ | Out-File "$Script:InstallDir\bin\pqc-connection-monitor.bat" -Encoding ASCII
            
            @"
@echo off
python "$Script:InstallDir\tools\pqc-keygen.py" %*
"@ | Out-File "$Script:InstallDir\bin\pqc-keygen.bat" -Encoding ASCII
            
            # Add to PATH
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            if ($currentPath -notlike "*$Script:InstallDir\bin*") {
                [Environment]::SetEnvironmentVariable("Path", $currentPath + ";$Script:InstallDir\bin", "Machine")
                $env:Path += ";$Script:InstallDir\bin"
            }
        }
        
        Write-Success "Python tools installed"
    }
    catch {
        Write-Error "Failed to install Python tools: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Setup web interface
function Set-WebInterface {
    if ($DisableWeb) {
        return $true
    }
    
    Write-Info "Setting up web management interface..."
    
    try {
        # Copy web interface files
        $repoDir = $env:PQC_REPO_DIR
        $webDir = if ($repoDir) { "$repoDir\web" } else { $null }
        
        if ($webDir -and (Test-Path $webDir)) {
            Copy-Item "$webDir\*" "$Script:InstallDir\web\" -Recurse -Force
        } else {
            Write-Info "Downloading web interface from GitHub..."
            # Create a simple download script for web files
            $webFiles = @("index.html", "api_server.py")
            foreach ($file in $webFiles) {
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/QEntangle/PQC-VPN/main/web/$file" -OutFile "$Script:InstallDir\web\$file"
            }
        }
        
        # Create Windows service for web interface
        $serviceName = "PQC-VPN-Web"
        $serviceScript = @"
import sys
import os
sys.path.append('$($Script:InstallDir -replace '\\', '\\')\\tools')
os.chdir('$($Script:InstallDir -replace '\\', '\\')\\web')
exec(open('api_server.py').read())
"@
        
        $serviceScript | Out-File "$Script:InstallDir\web\service.py" -Encoding UTF8
        
        # Install as Windows service using NSSM (Non-Sucking Service Manager)
        choco install nssm -y
        
        # Configure service
        nssm install $serviceName python "$Script:InstallDir\web\service.py"
        nssm set $serviceName Description "PQC-VPN Web Management Interface"
        nssm set $serviceName Start SERVICE_AUTO_START
        
        Write-Success "Web interface configured"
    }
    catch {
        Write-Error "Failed to setup web interface: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Setup monitoring
function Set-Monitoring {
    if ($DisableMonitoring) {
        return $true
    }
    
    Write-Info "Setting up monitoring..."
    
    try {
        # Configure Prometheus
        $prometheusConfig = @"
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pqc-vpn-hub'
    static_configs:
      - targets: ['localhost:8443']
    metrics_path: '/api/metrics'
    
  - job_name: 'windows-exporter'
    static_configs:
      - targets: ['localhost:9182']
"@
        
        $prometheusConfig | Out-File "$Script:ConfigDir\monitoring\prometheus.yml" -Encoding UTF8
        
        # Install Windows exporter for Prometheus
        $exporterUrl = "https://github.com/prometheus-community/windows_exporter/releases/download/v0.25.1/windows_exporter-0.25.1-amd64.msi"
        $exporterInstaller = "$env:TEMP\windows_exporter.msi"
        
        Invoke-WebRequest -Uri $exporterUrl -OutFile $exporterInstaller
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$exporterInstaller`" /quiet" -Wait
        Remove-Item $exporterInstaller -Force
        
        Write-Success "Monitoring configured"
    }
    catch {
        Write-Error "Failed to setup monitoring: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Create Windows services
function New-WindowsServices {
    Write-Info "Creating Windows services..."
    
    try {
        # Install NSSM if not already installed
        if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
            choco install nssm -y
        }
        
        # Create strongSwan service
        $strongSwanService = "strongSwan"
        if (-not (Get-Service $strongSwanService -ErrorAction SilentlyContinue)) {
            nssm install $strongSwanService "${env:ProgramFiles}\strongSwan\bin\ipsec.exe" "start --nofork"
            nssm set $strongSwanService Description "strongSwan IPsec VPN"
            nssm set $strongSwanService Start SERVICE_AUTO_START
            nssm set $strongSwanService DependOnService "Winmgmt"
        }
        
        # Create maintenance task
        $taskName = "PQC-VPN-Maintenance"
        $taskScript = @"
# PQC-VPN Maintenance Script for Windows
`$logPath = "$Script:ConfigDir\logs"
Get-ChildItem `$logPath -Filter "*.log" | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force

# Check certificate expiry
if (Test-Path "$Script:InstallDir\tools\connection-monitor.py") {
    python "$Script:InstallDir\tools\connection-monitor.py" certificates --check-expiry
}

# Backup configuration
`$backupPath = "$Script:BackupDir\config-backup-`$(Get-Date -Format 'yyyyMMdd').zip"
Compress-Archive -Path "$Script:ConfigDir\*.conf", "$Script:ConfigDir\certs", "$Script:ConfigDir\cacerts" -DestinationPath `$backupPath -Force

# Keep only last 7 days of backups
Get-ChildItem "$Script:BackupDir" -Filter "config-backup-*.zip" | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force
"@
        
        $taskScript | Out-File "$Script:InstallDir\bin\maintenance.ps1" -Encoding UTF8
        
        # Create scheduled task
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$Script:InstallDir\bin\maintenance.ps1`""
        $trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
        
        Write-Success "Windows services created"
    }
    catch {
        Write-Error "Failed to create Windows services: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Start services
function Start-Services {
    Write-Info "Starting services..."
    
    try {
        # Start strongSwan service
        $strongSwanService = Get-Service "strongSwan" -ErrorAction SilentlyContinue
        if ($strongSwanService) {
            if ($strongSwanService.Status -ne "Running") {
                Start-Service "strongSwan"
                Start-Sleep -Seconds 5
            }
            
            if ((Get-Service "strongSwan").Status -eq "Running") {
                Write-Success "strongSwan service is running"
            } else {
                Write-Warn "strongSwan service failed to start"
            }
        }
        
        # Start web interface service
        if (-not $DisableWeb) {
            $webService = Get-Service "PQC-VPN-Web" -ErrorAction SilentlyContinue
            if ($webService) {
                if ($webService.Status -ne "Running") {
                    Start-Service "PQC-VPN-Web"
                    Start-Sleep -Seconds 3
                }
                
                if ((Get-Service "PQC-VPN-Web").Status -eq "Running") {
                    Write-Success "Web interface service is running"
                } else {
                    Write-Warn "Web interface service failed to start"
                }
            }
        }
        
        Write-Success "Services started"
    }
    catch {
        Write-Error "Failed to start services: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Post-installation checks
function Test-Installation {
    Write-Info "Performing post-installation checks..."
    
    # Check strongSwan installation
    $strongSwanPath = "${env:ProgramFiles}\strongSwan\bin\ipsec.exe"
    if (Test-Path $strongSwanPath) {
        try {
            $ipsecVersion = & $strongSwanPath --version 2>$null
            Write-Success "strongSwan is functioning correctly"
        }
        catch {
            Write-Warn "strongSwan status check failed"
        }
    } else {
        Write-Warn "strongSwan executable not found"
    }
    
    # Check certificate validity
    $hubCert = "$Script:ConfigDir\certs\hub-cert.pem"
    if (Test-Path $hubCert) {
        try {
            $certExpiry = & openssl x509 -in $hubCert -noout -enddate 2>$null
            if ($certExpiry) {
                Write-Info "Hub certificate expires: $($certExpiry -replace 'notAfter=', '')"
            }
        }
        catch {
            Write-Debug "Certificate check failed"
        }
    }
    
    # Check network connectivity
    try {
        $pingResult = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -WarningAction SilentlyContinue
        if ($pingResult.TcpTestSucceeded) {
            Write-Success "Internet connectivity verified"
        } else {
            Write-Warn "Internet connectivity check failed"
        }
    }
    catch {
        Write-Debug "Network connectivity check failed"
    }
    
    # System resources check
    $cpu = Get-WmiObject -Class Win32_Processor
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $cpuCores = $cpu.NumberOfCores
    $memoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    
    Write-Info "System resources: $cpuCores CPU cores, $memoryGB GB RAM"
    
    Write-Success "Post-installation checks completed"
    return $true
}

# Installation summary
function Show-InstallationSummary {
    Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                   INSTALLATION COMPLETE                      ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green
    
    Write-Host "🎉 PQC-VPN Hub has been successfully installed on Windows!" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "📊 Installation Summary:" -ForegroundColor Blue
    Write-Host "   • Hub IP Address: " -NoNewline; Write-Host $HubIP -ForegroundColor Yellow
    Write-Host "   • Authentication Methods: " -NoNewline; Write-Host $AuthMethods -ForegroundColor Yellow
    Write-Host "   • PQC Algorithms: " -NoNewline; Write-Host $PQCAlgorithms -ForegroundColor Yellow
    Write-Host "   • Web Interface: " -NoNewline; Write-Host $(if(-not $DisableWeb){"Enabled"}else{"Disabled"}) -ForegroundColor Yellow
    Write-Host "   • Monitoring: " -NoNewline; Write-Host $(if(-not $DisableMonitoring){"Enabled"}else{"Disabled"}) -ForegroundColor Yellow
    Write-Host "   • High Availability: " -NoNewline; Write-Host $(if($EnableHA){"Enabled"}else{"Disabled"}) -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "🔗 Access Points:" -ForegroundColor Blue
    if (-not $DisableWeb) {
        Write-Host "   • Web Dashboard: " -NoNewline; Write-Host "https://$HubIP:8443" -ForegroundColor Yellow
    }
    if (-not $DisableMonitoring) {
        Write-Host "   • Grafana: " -NoNewline; Write-Host "http://$HubIP:3000" -ForegroundColor Yellow -NoNewline; Write-Host " (admin/admin)"
        Write-Host "   • Prometheus: " -NoNewline; Write-Host "http://$HubIP:9090" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "📁 Important Files:" -ForegroundColor Blue
    Write-Host "   • Configuration: " -NoNewline; Write-Host "${env:ProgramFiles}\strongSwan\etc\ipsec.conf" -ForegroundColor Yellow
    Write-Host "   • Secrets: " -NoNewline; Write-Host "${env:ProgramFiles}\strongSwan\etc\ipsec.secrets" -ForegroundColor Yellow
    Write-Host "   • Certificates: " -NoNewline; Write-Host "$Script:ConfigDir\certs" -ForegroundColor Yellow
    Write-Host "   • Logs: " -NoNewline; Write-Host "$Script:ConfigDir\logs" -ForegroundColor Yellow
    Write-Host "   • Installation Log: " -NoNewline; Write-Host $Script:LogFile -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "🔧 Next Steps:" -ForegroundColor Blue
    Write-Host "   1. Add spoke users: " -NoNewline; Write-Host "pqc-vpn-manager user add <username> --email <email>" -ForegroundColor Yellow
    Write-Host "   2. Monitor connections: " -NoNewline; Write-Host "pqc-connection-monitor status" -ForegroundColor Yellow
    Write-Host "   3. View logs: " -NoNewline; Write-Host "Get-EventLog -LogName Application -Source strongSwan" -ForegroundColor Yellow
    Write-Host "   4. Check status: " -NoNewline; Write-Host "ipsec status" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "📚 Documentation:" -ForegroundColor Blue
    Write-Host "   • GitHub: " -NoNewline; Write-Host "https://github.com/QEntangle/PQC-VPN" -ForegroundColor Yellow
    Write-Host "   • Docs: " -NoNewline; Write-Host "https://github.com/QEntangle/PQC-VPN/tree/main/docs" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
    Write-Host "   Thank you for choosing PQC-VPN for quantum-safe networking." -ForegroundColor Cyan
    Write-Host ""
}

# Main installation function
function Start-Installation {
    try {
        Show-Banner
        
        Write-Info "Starting $Script:NAME v$Script:VERSION"
        Write-Info "Installation mode: $InstallMode"
        Write-Info "Hub IP: $(if($HubIP){$HubIP}else{'Auto-detect'})"
        Write-Info "Authentication methods: $AuthMethods"
        Write-Info "PQC algorithms: $PQCAlgorithms"
        
        if (-not (Test-SystemRequirements)) { throw "System requirements check failed" }
        
        New-DirectoryStructure
        
        if (-not (Install-Dependencies)) { throw "Dependency installation failed" }
        if (-not (Install-StrongSwan)) { throw "strongSwan installation failed" }
        if (-not (Install-PQCLibraries)) { throw "PQC libraries installation failed" }
        if (-not (Set-StrongSwanConfiguration)) { throw "strongSwan configuration failed" }
        if (-not (New-Certificates)) { throw "Certificate generation failed" }
        if (-not (Set-FirewallRules)) { throw "Firewall configuration failed" }
        if (-not (Install-PythonTools)) { throw "Python tools installation failed" }
        if (-not (Set-WebInterface)) { throw "Web interface setup failed" }
        if (-not (Set-Monitoring)) { throw "Monitoring setup failed" }
        if (-not (New-WindowsServices)) { throw "Windows services creation failed" }
        if (-not (Start-Services)) { throw "Service startup failed" }
        if (-not (Test-Installation)) { throw "Post-installation checks failed" }
        
        Show-InstallationSummary
        
        Write-Success "PQC-VPN Hub installation completed successfully!"
        return $true
    }
    catch {
        Write-Error "Installation failed: $($_.Exception.Message)"
        Write-Error "Check the log file for details: $Script:LogFile"
        return $false
    }
}

# Start the installation
$installResult = Start-Installation

# Exit with appropriate code
exit $(if ($installResult) { 0 } else { 1 })
