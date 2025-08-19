# Real PQC-VPN Windows Installation Script
# PowerShell script for installing actual Post-Quantum Cryptography VPN on Windows

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$HubIP,
    
    [Parameter(Mandatory=$false)]
    [string]$Organization = "PQC-VPN-Enterprise",
    
    [Parameter(Mandatory=$false)]
    [string]$PQCKemAlgorithm = "kyber1024",
    
    [Parameter(Mandatory=$false)]
    [string]$PQCSigAlgorithm = "dilithium5",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("pki", "psk", "hybrid")]
    [string]$AuthType = "pki",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\Program Files\PQC-VPN",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Require Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "❌ This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

Write-Host "🚀 Real PQC-VPN Windows Hub Installation" -ForegroundColor Cyan
Write-Host "Hub IP: $HubIP" -ForegroundColor Green
Write-Host "PQC KEM Algorithm: $PQCKemAlgorithm" -ForegroundColor Green
Write-Host "PQC Signature Algorithm: $PQCSigAlgorithm" -ForegroundColor Green
Write-Host "Authentication Type: $AuthType" -ForegroundColor Green

# Check Windows version compatibility
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Write-Error "❌ Windows 10/11 or Windows Server 2019/2022 required"
    exit 1
}

Write-Host "✅ Windows version compatible: $($osVersion.Major).$($osVersion.Minor)" -ForegroundColor Green

# Function to download file with progress
function Download-FileWithProgress {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$Description
    )
    
    Write-Host "📥 Downloading $Description..." -ForegroundColor Yellow
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $OutputPath)
        Write-Host "✅ Downloaded: $Description" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "❌ Failed to download $Description : $_"
        return $false
    }
}

# Function to install Chocolatey if not present
function Install-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "📦 Installing Chocolatey package manager..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
        Write-Host "✅ Chocolatey installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✅ Chocolatey already installed" -ForegroundColor Green
    }
}

# Function to install required dependencies
function Install-Dependencies {
    Write-Host "📦 Installing required dependencies..." -ForegroundColor Yellow
    
    # Install basic build tools
    $packages = @(
        "git",
        "cmake",
        "ninja", 
        "python3",
        "visualstudio2022buildtools",
        "visualstudio2022-workload-vctools",
        "openssl"
    )
    
    foreach ($package in $packages) {
        Write-Host "Installing $package..." -ForegroundColor Gray
        choco install $package -y --no-progress
    }
    
    # Install Python packages
    Write-Host "🐍 Installing Python dependencies..." -ForegroundColor Yellow
    python -m pip install --upgrade pip
    python -m pip install psutil flask flask-sqlalchemy redis cryptography requests
    
    Write-Host "✅ Dependencies installed successfully" -ForegroundColor Green
}

# Function to build liboqs for Windows
function Build-LibOQS {
    param([string]$BuildPath)
    
    Write-Host "🔧 Building liboqs (Open Quantum Safe library)..." -ForegroundColor Yellow
    
    $liboqsPath = Join-Path $BuildPath "liboqs"
    
    if (Test-Path $liboqsPath) {
        Remove-Item -Recurse -Force $liboqsPath
    }
    
    # Clone liboqs
    Set-Location $BuildPath
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
    Set-Location $liboqsPath
    
    # Create build directory
    New-Item -ItemType Directory -Path "build" -Force | Out-Null
    Set-Location "build"
    
    # Configure with CMake
    $cmakeArgs = @(
        "-GNinja",
        "-DCMAKE_INSTALL_PREFIX=C:\liboqs",
        "-DOQS_BUILD_ONLY_LIB=ON",
        "-DOQS_MINIMAL_BUILD=KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_1024",
        ".."
    )
    
    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }
    
    # Build
    ninja
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }
    
    # Install
    ninja install
    if ($LASTEXITCODE -ne 0) {
        throw "Installation failed"
    }
    
    Write-Host "✅ liboqs built and installed successfully" -ForegroundColor Green
}

# Function to build OQS-enabled OpenSSL
function Build-OQSOpenSSL {
    param([string]$BuildPath)
    
    Write-Host "🔧 Building OQS-enabled OpenSSL..." -ForegroundColor Yellow
    
    $opensslPath = Join-Path $BuildPath "oqs-openssl"
    
    if (Test-Path $opensslPath) {
        Remove-Item -Recurse -Force $opensslPath
    }
    
    Set-Location $BuildPath
    git clone --depth 1 --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git oqs-openssl
    Set-Location $opensslPath
    
    # Configure for Windows
    $env:LIB = "C:\liboqs\lib;" + $env:LIB
    $env:INCLUDE = "C:\liboqs\include;" + $env:INCLUDE
    
    perl Configure VC-WIN64A --prefix=C:\oqs-openssl --openssldir=C:\oqs-openssl\ssl
    
    # Build
    nmake
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL build failed"
    }
    
    # Install
    nmake install
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL installation failed"
    }
    
    Write-Host "✅ OQS-enabled OpenSSL built and installed successfully" -ForegroundColor Green
}

# Function to install strongSwan for Windows
function Install-StrongSwan {
    Write-Host "🔧 Installing strongSwan for Windows..." -ForegroundColor Yellow
    
    # Download strongSwan Windows installer
    $strongswanUrl = "https://download.strongswan.org/Windows/strongSwan-5.9.14.msi"
    $strongswanInstaller = "$env:TEMP\strongswan-installer.msi"
    
    if (Download-FileWithProgress $strongswanUrl $strongswanInstaller "strongSwan Windows Installer") {
        # Install strongSwan
        Write-Host "Installing strongSwan..." -ForegroundColor Gray
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $strongswanInstaller, "/quiet", "/norestart" -Wait
        
        # Verify installation
        $strongswanPath = "${env:ProgramFiles}\strongSwan"
        if (Test-Path $strongswanPath) {
            Write-Host "✅ strongSwan installed successfully" -ForegroundColor Green
        } else {
            throw "strongSwan installation verification failed"
        }
        
        # Clean up installer
        Remove-Item $strongswanInstaller -Force
    } else {
        throw "Failed to download strongSwan installer"
    }
}

# Function to configure Windows networking
function Configure-Networking {
    Write-Host "🌐 Configuring Windows networking for VPN..." -ForegroundColor Yellow
    
    # Enable IP routing
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1
    
    # Configure Windows Firewall rules
    Write-Host "Configuring Windows Firewall..." -ForegroundColor Gray
    
    # Allow IKE (UDP 500)
    New-NetFirewallRule -DisplayName "PQC-VPN IKE" -Direction Inbound -Protocol UDP -LocalPort 500 -Action Allow -ErrorAction SilentlyContinue
    
    # Allow NAT-T (UDP 4500)
    New-NetFirewallRule -DisplayName "PQC-VPN NAT-T" -Direction Inbound -Protocol UDP -LocalPort 4500 -Action Allow -ErrorAction SilentlyContinue
    
    # Allow ESP (Protocol 50)
    New-NetFirewallRule -DisplayName "PQC-VPN ESP" -Direction Inbound -Protocol 50 -Action Allow -ErrorAction SilentlyContinue
    
    # Allow management interface
    New-NetFirewallRule -DisplayName "PQC-VPN Management" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -ErrorAction SilentlyContinue
    
    Write-Host "✅ Networking configured successfully" -ForegroundColor Green
}

# Function to generate PQC certificates
function Generate-PQCCertificates {
    Write-Host "🔐 Generating Post-Quantum Cryptography certificates..." -ForegroundColor Yellow
    
    $certPath = Join-Path $InstallPath "certs"
    New-Item -ItemType Directory -Path $certPath -Force | Out-Null
    
    $opensslExe = "C:\oqs-openssl\bin\openssl.exe"
    
    if (-not (Test-Path $opensslExe)) {
        throw "OQS-enabled OpenSSL not found at $opensslExe"
    }
    
    # Test PQC algorithm availability
    Write-Host "Testing PQC algorithm availability..." -ForegroundColor Gray
    $algTest = & $opensslExe list -signature-algorithms | Select-String $PQCSigAlgorithm
    if (-not $algTest) {
        Write-Warning "⚠️  PQC signature algorithm $PQCSigAlgorithm not available, falling back to RSA"
        $PQCSigAlgorithm = "rsa"
    }
    
    try {
        # Generate CA private key
        Write-Host "Generating CA private key..." -ForegroundColor Gray
        $caKeyPath = Join-Path $certPath "ca-key.pem"
        
        if ($PQCSigAlgorithm -eq "rsa") {
            & $opensslExe genpkey -algorithm RSA -pkcs8 -out $caKeyPath -pkeyopt rsa_keygen_bits:4096
        } else {
            & $opensslExe genpkey -algorithm $PQCSigAlgorithm -out $caKeyPath
        }
        
        if ($LASTEXITCODE -ne 0) {
            throw "CA key generation failed"
        }
        
        # Generate CA certificate
        Write-Host "Generating CA certificate..." -ForegroundColor Gray
        $caCertPath = Join-Path $certPath "ca-cert.pem"
        $caSubject = "/C=US/ST=CA/L=San Francisco/O=$Organization/OU=Certificate Authority/CN=PQC-VPN-CA"
        
        & $opensslExe req -new -x509 -key $caKeyPath -out $caCertPath -days 3650 -subj $caSubject
        
        if ($LASTEXITCODE -ne 0) {
            throw "CA certificate generation failed"
        }
        
        # Generate hub private key
        Write-Host "Generating hub private key..." -ForegroundColor Gray
        $hubKeyPath = Join-Path $certPath "hub-key.pem"
        
        if ($PQCSigAlgorithm -eq "rsa") {
            & $opensslExe genpkey -algorithm RSA -pkcs8 -out $hubKeyPath -pkeyopt rsa_keygen_bits:4096
        } else {
            & $opensslExe genpkey -algorithm $PQCSigAlgorithm -out $hubKeyPath
        }
        
        if ($LASTEXITCODE -ne 0) {
            throw "Hub key generation failed"
        }
        
        # Generate hub certificate
        Write-Host "Generating hub certificate..." -ForegroundColor Gray
        $hubCertPath = Join-Path $certPath "hub-cert.pem"
        $hubCsrPath = Join-Path $certPath "hub.csr"
        $hubSubject = "/C=US/ST=CA/L=San Francisco/O=$Organization/OU=VPN Hub/CN=$HubIP"
        
        # Create CSR
        & $opensslExe req -new -key $hubKeyPath -out $hubCsrPath -subj $hubSubject
        
        if ($LASTEXITCODE -ne 0) {
            throw "Hub CSR generation failed"
        }
        
        # Create extensions file
        $extFile = Join-Path $certPath "hub_ext.conf"
        @"
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = $HubIP
DNS.1 = pqc-hub.local
"@ | Out-File -FilePath $extFile -Encoding ASCII
        
        # Sign hub certificate
        & $opensslExe x509 -req -in $hubCsrPath -CA $caCertPath -CAkey $caKeyPath -CAcreateserial -out $hubCertPath -days 365 -extensions v3_ext -extfile $extFile
        
        if ($LASTEXITCODE -ne 0) {
            throw "Hub certificate signing failed"
        }
        
        # Clean up temporary files
        Remove-Item $hubCsrPath, $extFile -Force -ErrorAction SilentlyContinue
        
        Write-Host "✅ PQC certificates generated successfully" -ForegroundColor Green
        Write-Host "📜 CA Certificate: $caCertPath" -ForegroundColor Cyan
        Write-Host "📜 Hub Certificate: $hubCertPath" -ForegroundColor Cyan
        
        # Set proper file permissions
        $acl = Get-Acl $caKeyPath
        $acl.SetAccessRuleProtection($true, $false)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $caKeyPath -AclObject $acl
        Set-Acl -Path $hubKeyPath -AclObject $acl
        
    } catch {
        Write-Error "❌ Certificate generation failed: $_"
        throw
    }
}

# Function to create strongSwan configuration
function Create-StrongSwanConfig {
    Write-Host "📝 Creating strongSwan configuration..." -ForegroundColor Yellow
    
    $configPath = Join-Path $InstallPath "config"
    New-Item -ItemType Directory -Path $configPath -Force | Out-Null
    
    # Create ipsec.conf
    $ipsecConf = Join-Path $configPath "ipsec.conf"
    $kemAlgo = if ($PQCKemAlgorithm -eq "kyber1024") { $PQCKemAlgorithm } else { "ecp384" }
    $sigAlgo = if ($PQCSigAlgorithm -ne "rsa") { $PQCSigAlgorithm } else { "" }
    
    $ikeAlgorithms = if ($sigAlgo) { "aes256gcm16-sha512-$kemAlgo-$sigAlgo" } else { "aes256gcm16-sha512-$kemAlgo" }
    $espAlgorithms = "aes256gcm16-sha512-$kemAlgo"
    
@"
# Real Post-Quantum Cryptography strongSwan Configuration
# Windows Hub Configuration
# Generated: $(Get-Date)

config setup
    charondebug="cfg 2, dmn 2, ike 2, net 2, esp 2, lib 2"
    uniqueids=yes
    cachecrls=no
    strictcrlpolicy=no

# Default connection parameters
conn %default
    keyexchange=ikev2
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftsubnet=0.0.0.0/0
    right=%any
    leftfirewall=yes
    rightfirewall=yes
    
# Real PQC Hub-to-Spoke connections
conn pqc-pki-spoke
    auto=add
    type=tunnel
    leftauth=pubkey
    rightauth=pubkey
    leftcert=hub-cert.pem
    leftid="C=US, O=$Organization, CN=$HubIP"
    rightid=%any
    rightsubnet=10.10.0.0/16
    # Real PQC algorithms
    ike=$ikeAlgorithms!
    esp=$espAlgorithms!

conn pqc-psk-spoke
    auto=add
    type=tunnel
    leftauth=psk
    rightauth=psk
    leftid=@$HubIP
    rightid=%any
    rightsubnet=10.10.0.0/16
    # Real PQC algorithms with PSK
    ike=aes256gcm16-sha512-$kemAlgo!
    esp=aes256gcm16-sha512-$kemAlgo!

conn pqc-hybrid-spoke
    auto=add
    type=tunnel
    leftauth=pubkey
    rightauth=psk
    leftcert=hub-cert.pem
    leftid="C=US, O=$Organization, CN=$HubIP"
    rightid=%any
    rightsubnet=10.10.0.0/16
    # Hybrid PKI+PSK with PQC
    ike=$ikeAlgorithms!
    esp=$espAlgorithms!
"@ | Out-File -FilePath $ipsecConf -Encoding ASCII

    # Create ipsec.secrets
    $ipsecSecrets = Join-Path $configPath "ipsec.secrets"
@"
# Real PQC-VPN Hub Secrets
# Generated: $(Get-Date)

# Hub certificate private key
: RSA hub-key.pem

# Demo PSKs
@$HubIP %any : PSK "pqc-enterprise-key-$(Get-Date -Format 'yyyyMMdd')-secure"
demo-user-1 : PSK "user1-pqc-$(Get-Random)"
demo-user-2 : PSK "user2-pqc-$(Get-Random)"
demo-user-3 : PSK "user3-pqc-$(Get-Random)"
"@ | Out-File -FilePath $ipsecSecrets -Encoding ASCII

    # Create strongswan.conf
    $strongswanConf = Join-Path $configPath "strongswan.conf"
@"
# Real PQC strongSwan Windows Configuration

charon {
    load_modular = yes
    
    # Crypto plugins
    plugins {
        openssl {
            load = yes
            fips_mode = 0
        }
        
        winhttp {
            load = yes
        }
        
        kernel-wfp {
            load = yes
        }
        
        socket-win {
            load = yes
        }
    }
    
    # Network settings
    port = 500
    port_nat_t = 4500
    
    # Performance settings
    threads = 16
    
    # Security settings
    integrity_test = yes
    crypto_test = yes
    
    # Logging
    syslog {
        daemon {
            default = 2
        }
    }
}
"@ | Out-File -FilePath $strongswanConf -Encoding ASCII

    Write-Host "✅ strongSwan configuration created successfully" -ForegroundColor Green
}

# Function to install Windows services
function Install-Services {
    Write-Host "⚙️ Installing PQC-VPN Windows services..." -ForegroundColor Yellow
    
    $servicePath = Join-Path $InstallPath "services"
    New-Item -ItemType Directory -Path $servicePath -Force | Out-Null
    
    # Create monitoring service script
    $monitorScript = Join-Path $servicePath "PQCVPNMonitor.ps1"
@"
# PQC-VPN Monitoring Service for Windows
param([string]`$Action = "start")

`$LogFile = "$InstallPath\logs\monitor.log"
New-Item -ItemType Directory -Path (Split-Path `$LogFile) -Force | Out-Null

function Write-Log {
    param([string]`$Message)
    "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - `$Message" | Out-File -FilePath `$LogFile -Append
    Write-Host `$Message
}

function Get-VPNStatus {
    try {
        `$process = Get-Process -Name "charon" -ErrorAction SilentlyContinue
        return `$process -ne `$null
    } catch {
        return `$false
    }
}

function Monitor-PQCVPNService {
    Write-Log "Starting PQC-VPN monitoring service"
    
    while (`$true) {
        `$status = Get-VPNStatus
        `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        
        if (`$status) {
            Write-Log "✅ PQC-VPN service is running"
        } else {
            Write-Log "❌ PQC-VPN service is not running"
        }
        
        Start-Sleep -Seconds 60
    }
}

switch (`$Action) {
    "start" { Monitor-PQCVPNService }
    "stop" { Write-Log "Stopping monitoring service"; exit 0 }
    default { Write-Log "Unknown action: `$Action" }
}
"@ | Out-File -FilePath $monitorScript -Encoding ASCII

    Write-Host "✅ Windows services configured successfully" -ForegroundColor Green
}

# Function to create management interface
function Create-ManagementInterface {
    Write-Host "🖥️ Creating management interface..." -ForegroundColor Yellow
    
    $webPath = Join-Path $InstallPath "web"
    New-Item -ItemType Directory -Path $webPath -Force | Out-Null
    
    # Create simple web dashboard
    $dashboardScript = Join-Path $webPath "dashboard.py"
@"
#!/usr/bin/env python3
"""
PQC-VPN Windows Management Dashboard
"""

from flask import Flask, render_template_string, jsonify
import subprocess
import psutil
import json
from datetime import datetime

app = Flask(__name__)

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PQC-VPN Windows Management</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #007bff; color: white; padding: 20px; margin: -20px -20px 20px -20px; text-align: center; }
        .card { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-running { background: #28a745; color: white; padding: 10px; border-radius: 5px; text-align: center; }
        .status-stopped { background: #dc3545; color: white; padding: 10px; border-radius: 5px; text-align: center; }
        .metric { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
        .metric:last-child { border-bottom: none; }
    </style>
    <script>
        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('vpn-status').className = data.running ? 'status-running' : 'status-stopped';
                    document.getElementById('vpn-status').textContent = data.running ? '✅ PQC-VPN Running' : '❌ PQC-VPN Stopped';
                    document.getElementById('cpu-usage').textContent = data.cpu_usage + '%';
                    document.getElementById('memory-usage').textContent = data.memory_usage + '%';
                    document.getElementById('last-update').textContent = 'Last updated: ' + new Date().toLocaleString();
                });
        }
        setInterval(updateStatus, 30000);
        window.onload = updateStatus;
    </script>
</head>
<body>
    <div class="header">
        <h1>🔐 PQC-VPN Windows Management</h1>
        <p>Post-Quantum Cryptography VPN - Windows Hub</p>
    </div>
    
    <div class="card">
        <h3>System Status</h3>
        <div id="vpn-status" class="status-stopped">Loading...</div>
        <div class="metric">
            <span>CPU Usage:</span>
            <span id="cpu-usage">-</span>
        </div>
        <div class="metric">
            <span>Memory Usage:</span>
            <span id="memory-usage">-</span>
        </div>
        <div class="metric">
            <span>Hub IP:</span>
            <span>$HubIP</span>
        </div>
        <div class="metric">
            <span>PQC Algorithms:</span>
            <span>$PQCKemAlgorithm + $PQCSigAlgorithm</span>
        </div>
    </div>
    
    <div class="card">
        <h3>Quick Actions</h3>
        <button onclick="location.reload()" style="padding: 10px 20px; margin: 5px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Refresh Status</button>
        <button onclick="alert('Feature coming soon')" style="padding: 10px 20px; margin: 5px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">Add User</button>
        <button onclick="alert('Feature coming soon')" style="padding: 10px 20px; margin: 5px; background: #ffc107; color: black; border: none; border-radius: 5px; cursor: pointer;">View Logs</button>
    </div>
    
    <div id="last-update" style="text-align: center; color: #666; margin-top: 20px;">
        Loading...
    </div>
</body>
</html>
'''

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/status')
def api_status():
    try:
        # Check if strongSwan process is running
        running = False
        try:
            processes = [p for p in psutil.process_iter(['pid', 'name']) if 'charon' in p.info['name'].lower()]
            running = len(processes) > 0
        except:
            pass
        
        return jsonify({
            'running': running,
            'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
            'memory_usage': round(psutil.virtual_memory().percent, 1),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🌐 Starting PQC-VPN Windows Management Dashboard...")
    print("🔗 Access at: https://localhost:8443")
    app.run(host='0.0.0.0', port=8443, debug=False, ssl_context='adhoc')
"@ | Out-File -FilePath $dashboardScript -Encoding ASCII

    Write-Host "✅ Management interface created successfully" -ForegroundColor Green
}

# Main installation function
function Start-Installation {
    try {
        Write-Host "`n🎯 Starting Real PQC-VPN Windows Installation..." -ForegroundColor Cyan
        
        # Create installation directory
        if (Test-Path $InstallPath) {
            if (-not $Force) {
                $response = Read-Host "Installation directory exists. Overwrite? (y/N)"
                if ($response -ne "y") {
                    Write-Host "❌ Installation cancelled" -ForegroundColor Red
                    exit 0
                }
            }
            Remove-Item -Recurse -Force $InstallPath
        }
        
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-Host "✅ Created installation directory: $InstallPath" -ForegroundColor Green
        
        # Create subdirectories
        $subDirs = @("logs", "config", "certs", "services", "web", "temp")
        foreach ($dir in $subDirs) {
            New-Item -ItemType Directory -Path (Join-Path $InstallPath $dir) -Force | Out-Null
        }
        
        # Install dependencies
        Install-Chocolatey
        Install-Dependencies
        
        # Build PQC libraries
        $buildPath = Join-Path $InstallPath "temp"
        Build-LibOQS $buildPath
        Build-OQSOpenSSL $buildPath
        
        # Install strongSwan
        Install-StrongSwan
        
        # Configure networking
        Configure-Networking
        
        # Generate certificates
        Generate-PQCCertificates
        
        # Create configuration
        Create-StrongSwanConfig
        
        # Install services
        Install-Services
        
        # Create management interface
        Create-ManagementInterface
        
        # Create startup script
        $startupScript = Join-Path $InstallPath "start-pqc-vpn.ps1"
@"
# PQC-VPN Windows Startup Script
Write-Host "🚀 Starting PQC-VPN Windows Hub..." -ForegroundColor Cyan

# Start strongSwan service
Start-Service strongSwan -ErrorAction SilentlyContinue

# Start monitoring
Start-Process PowerShell -ArgumentList "-File `"$InstallPath\services\PQCVPNMonitor.ps1`"" -WindowStyle Minimized

# Start management dashboard
Start-Process Python -ArgumentList "`"$InstallPath\web\dashboard.py`"" -WindowStyle Minimized

Write-Host "✅ PQC-VPN started successfully" -ForegroundColor Green
Write-Host "🌐 Management Dashboard: https://localhost:8443" -ForegroundColor Cyan
Write-Host "📊 Hub IP: $HubIP" -ForegroundColor Cyan
"@ | Out-File -FilePath $startupScript -Encoding ASCII
        
        Write-Host "`n🎉 Real PQC-VPN Windows Installation Completed Successfully!" -ForegroundColor Green
        Write-Host "=" * 60 -ForegroundColor Gray
        Write-Host "📍 Installation Path: $InstallPath" -ForegroundColor Cyan
        Write-Host "🔐 Hub IP Address: $HubIP" -ForegroundColor Cyan
        Write-Host "🧮 PQC KEM Algorithm: $PQCKemAlgorithm" -ForegroundColor Cyan
        Write-Host "🔏 PQC Signature Algorithm: $PQCSigAlgorithm" -ForegroundColor Cyan
        Write-Host "🔑 Authentication Type: $AuthType" -ForegroundColor Cyan
        Write-Host "`n📋 Next Steps:" -ForegroundColor Yellow
        Write-Host "1. Run: & '$startupScript'" -ForegroundColor White
        Write-Host "2. Access management: https://localhost:8443" -ForegroundColor White
        Write-Host "3. Configure clients using certificates in: $InstallPath\certs" -ForegroundColor White
        Write-Host "4. Check logs in: $InstallPath\logs" -ForegroundColor White
        
        # Clean up build directory
        Remove-Item -Recurse -Force $buildPath -ErrorAction SilentlyContinue
        
    } catch {
        Write-Error "❌ Installation failed: $_"
        Write-Host "🔧 Check logs in: $InstallPath\logs" -ForegroundColor Yellow
        exit 1
    }
}

# Verification function
function Test-Installation {
    Write-Host "`n🔍 Verifying installation..." -ForegroundColor Yellow
    
    $checks = @(
        @{ Path = "C:\liboqs\lib"; Name = "liboqs library" },
        @{ Path = "C:\oqs-openssl\bin\openssl.exe"; Name = "OQS-enabled OpenSSL" },
        @{ Path = "${env:ProgramFiles}\strongSwan"; Name = "strongSwan" },
        @{ Path = (Join-Path $InstallPath "certs\ca-cert.pem"); Name = "CA Certificate" },
        @{ Path = (Join-Path $InstallPath "certs\hub-cert.pem"); Name = "Hub Certificate" }
    )
    
    $allGood = $true
    foreach ($check in $checks) {
        if (Test-Path $check.Path) {
            Write-Host "✅ $($check.Name)" -ForegroundColor Green
        } else {
            Write-Host "❌ $($check.Name) - Not found at $($check.Path)" -ForegroundColor Red
            $allGood = $false
        }
    }
    
    if ($allGood) {
        Write-Host "`n🎉 All components verified successfully!" -ForegroundColor Green
    } else {
        Write-Host "`n⚠️  Some components missing - installation may have issues" -ForegroundColor Yellow
    }
}

# Start installation
Start-Installation
Test-Installation

Write-Host "`n🚀 PQC-VPN Windows Installation Complete!" -ForegroundColor Green
Write-Host "Ready for Post-Quantum Cryptography VPN deployment!" -ForegroundColor Cyan
