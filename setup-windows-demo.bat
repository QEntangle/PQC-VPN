@echo off
:: PQC-VPN Windows Demo Quick Setup
:: Automates the setup of 1 server + 3 clients demo

setlocal enabledelayedexpansion

:: Colors for output (Windows 10+)
set "GREEN=[92m"
set "BLUE=[94m"
set "YELLOW=[93m"
set "RED=[91m"
set "NC=[0m"

echo %BLUE%🔐 PQC-VPN Windows Demo Setup%NC%
echo ========================================

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%❌ This script requires administrator privileges%NC%
    echo Please run as administrator and try again.
    pause
    exit /b 1
)

:: Set base directory
set "BASE_DIR=%CD%"
set "DEMO_DIR=%BASE_DIR%\demo-setup"

echo %BLUE%📂 Setting up demo directories...%NC%
if not exist "%DEMO_DIR%" mkdir "%DEMO_DIR%"
if not exist "%DEMO_DIR%\hub" mkdir "%DEMO_DIR%\hub"
if not exist "%DEMO_DIR%\client-alice" mkdir "%DEMO_DIR%\client-alice"
if not exist "%DEMO_DIR%\client-bob" mkdir "%DEMO_DIR%\client-bob"
if not exist "%DEMO_DIR%\client-charlie" mkdir "%DEMO_DIR%\client-charlie"
if not exist "%DEMO_DIR%\logs" mkdir "%DEMO_DIR%\logs"

:: Check Docker installation
echo %BLUE%🐳 Checking Docker installation...%NC%
docker --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%❌ Docker is not installed or not in PATH%NC%
    echo Please install Docker Desktop from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
) else (
    echo %GREEN%✅ Docker found%NC%
)

:: Check Python installation
echo %BLUE%🐍 Checking Python installation...%NC%
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%❌ Python is not installed or not in PATH%NC%
    echo Please install Python 3.8+ from: https://www.python.org/downloads/
    pause
    exit /b 1
) else (
    echo %GREEN%✅ Python found%NC%
)

:: Install Python dependencies
echo %BLUE%📦 Installing Python dependencies...%NC%
pip install flask flask-cors psutil pyyaml >nul 2>&1
if %errorLevel% equ 0 (
    echo %GREEN%✅ Python packages installed%NC%
) else (
    echo %YELLOW%⚠️  Warning: Some packages may have failed to install%NC%
)

:: Generate demo configurations
echo %BLUE%⚙️  Generating demo configurations...%NC%

:: Hub configuration
echo %BLUE%Creating hub configuration...%NC%
(
echo config setup
echo     charondebug="ike 2, knl 2, cfg 2"
echo     strictcrlpolicy=no
echo.
echo conn %%default
echo     keyexchange=ikev2
echo     ike=aes256-sha256-x25519,aes256-sha256-kyber1024!
echo     esp=aes256-sha256-x25519,aes256-sha256-kyber1024!
echo     dpdaction=clear
echo     dpddelay=300s
echo     rekey=no
echo     left=10.10.0.1
echo     leftsubnet=10.10.0.0/16
echo     leftcert=hub-cert.pem
echo     leftid="C=US, O=PQC-VPN Demo, CN=hub.pqc-demo.local"
echo.
echo conn alice-pki
echo     auto=add
echo     right=10.10.1.50
echo     rightsubnet=10.10.1.50/32
echo     rightid="C=US, O=PQC-VPN Demo, CN=alice.pqc-demo.local"
echo     rightcert=alice-cert.pem
echo.
echo conn bob-psk
echo     auto=add
echo     right=10.10.1.51
echo     rightsubnet=10.10.1.51/32
echo     rightid=bob
echo     authby=secret
echo     ike=aes256-sha256-kyber768!
echo     esp=aes256-sha256-kyber768!
echo.
echo conn charlie-hybrid
echo     auto=add
echo     right=10.10.1.52
echo     rightsubnet=10.10.1.52/32
echo     rightid="C=US, O=PQC-VPN Demo, CN=charlie.pqc-demo.local"
echo     rightcert=charlie-cert.pem
echo     authby=secret
echo     ike=aes256-sha256-kyber512!
echo     esp=aes256-sha256-kyber512!
) > "%DEMO_DIR%\hub\ipsec.conf"

:: Hub secrets
(
echo # Hub secrets for demo
echo : RSA hub-key.pem
echo bob : PSK "demo-psk-key-bob-2025"
echo charlie : PSK "demo-psk-key-charlie-2025"
) > "%DEMO_DIR%\hub\ipsec.secrets"

:: Alice configuration (PKI)
echo %BLUE%Creating Alice ^(PKI^) configuration...%NC%
(
echo config setup
echo     charondebug="ike 2, knl 2, cfg 2"
echo     strictcrlpolicy=no
echo.
echo conn %%default
echo     keyexchange=ikev2
echo     ike=aes256-sha256-kyber1024!
echo     esp=aes256-sha256-kyber1024!
echo     dpdaction=restart
echo     dpddelay=300s
echo     rekey=no
echo     right=10.10.0.1
echo     rightsubnet=10.10.0.0/16
echo     rightid="C=US, O=PQC-VPN Demo, CN=hub.pqc-demo.local"
echo     left=10.10.1.50
echo     leftsubnet=10.10.1.50/32
echo     leftcert=alice-cert.pem
echo     leftid="C=US, O=PQC-VPN Demo, CN=alice.pqc-demo.local"
echo     auto=start
echo.
echo conn hub
echo     rightcert=hub-cert.pem
) > "%DEMO_DIR%\client-alice\ipsec.conf"

:: Alice secrets
echo : RSA alice-key.pem > "%DEMO_DIR%\client-alice\ipsec.secrets"

:: Bob configuration (PSK)
echo %BLUE%Creating Bob ^(PSK^) configuration...%NC%
(
echo config setup
echo     charondebug="ike 2, knl 2, cfg 2"
echo     strictcrlpolicy=no
echo.
echo conn %%default
echo     keyexchange=ikev2
echo     ike=aes256-sha256-kyber768!
echo     esp=aes256-sha256-kyber768!
echo     dpdaction=restart
echo     dpddelay=300s
echo     rekey=no
echo     right=10.10.0.1
echo     rightsubnet=10.10.0.0/16
echo     rightid=hub
echo     left=10.10.1.51
echo     leftsubnet=10.10.1.51/32
echo     leftid=bob
echo     authby=secret
echo     auto=start
echo.
echo conn hub
) > "%DEMO_DIR%\client-bob\ipsec.conf"

:: Bob secrets
echo bob hub : PSK "demo-psk-key-bob-2025" > "%DEMO_DIR%\client-bob\ipsec.secrets"

:: Charlie configuration (Hybrid)
echo %BLUE%Creating Charlie ^(Hybrid^) configuration...%NC%
(
echo config setup
echo     charondebug="ike 2, knl 2, cfg 2"
echo     strictcrlpolicy=no
echo.
echo conn %%default
echo     keyexchange=ikev2
echo     ike=aes256-sha256-kyber512!
echo     esp=aes256-sha256-kyber512!
echo     dpdaction=restart
echo     dpddelay=300s
echo     rekey=no
echo     right=10.10.0.1
echo     rightsubnet=10.10.0.0/16
echo     rightid="C=US, O=PQC-VPN Demo, CN=hub.pqc-demo.local"
echo     left=10.10.1.52
echo     leftsubnet=10.10.1.52/32
echo     leftcert=charlie-cert.pem
echo     leftid="C=US, O=PQC-VPN Demo, CN=charlie.pqc-demo.local"
echo     authby=secret
echo     auto=start
echo.
echo conn hub
echo     rightcert=hub-cert.pem
) > "%DEMO_DIR%\client-charlie\ipsec.conf"

:: Charlie secrets
(
echo : RSA charlie-key.pem
echo charlie hub : PSK "demo-psk-key-charlie-2025"
) > "%DEMO_DIR%\client-charlie\ipsec.secrets"

:: Create terminal launcher scripts
echo %BLUE%📝 Creating terminal launcher scripts...%NC%

:: Hub launcher
(
echo @echo off
echo title PQC-VPN Hub Server
echo cd /d "%DEMO_DIR%\hub"
echo echo Starting PQC-VPN Hub Server...
echo echo.
echo echo %GREEN%🔐 Hub Server Configuration:%NC%
echo echo   • Network: 10.10.0.0/16
echo echo   • Algorithms: Kyber-1024, Kyber-768, Kyber-512
echo echo   • Auth: PKI + PSK + Hybrid
echo echo.
echo docker run -it --rm --name pqc-vpn-hub ^
echo   --cap-add=NET_ADMIN ^
echo   --device=/dev/net/tun ^
echo   -v "%DEMO_DIR%\hub":/etc/ipsec.d ^
echo   -p 500:500/udp ^
echo   -p 4500:4500/udp ^
echo   pqc-vpn:latest ^
echo   /bin/bash -c "ipsec start --nofork"
echo pause
) > "%DEMO_DIR%\start-hub.bat"

:: Alice launcher
(
echo @echo off
echo title PQC-VPN Client - Alice ^(PKI^)
echo cd /d "%DEMO_DIR%\client-alice"
echo echo Starting Alice - PKI Authentication with Kyber-1024...
echo echo.
echo echo %GREEN%👩 Alice Configuration:%NC%
echo echo   • IP: 10.10.1.50
echo echo   • Auth: PKI ^(Certificate-based^)
echo echo   • Algorithm: Kyber-1024
echo echo.
echo timeout /t 15 /nobreak
echo docker run -it --rm --name pqc-vpn-alice ^
echo   --cap-add=NET_ADMIN ^
echo   --device=/dev/net/tun ^
echo   -v "%DEMO_DIR%\client-alice":/etc/ipsec.d ^
echo   pqc-vpn:latest ^
echo   /bin/bash -c "ipsec start --nofork"
echo pause
) > "%DEMO_DIR%\start-alice.bat"

:: Bob launcher
(
echo @echo off
echo title PQC-VPN Client - Bob ^(PSK^)
echo cd /d "%DEMO_DIR%\client-bob"
echo echo Starting Bob - PSK Authentication with Kyber-768...
echo echo.
echo echo %GREEN%👨 Bob Configuration:%NC%
echo echo   • IP: 10.10.1.51
echo echo   • Auth: PSK ^(Pre-shared Key^)
echo echo   • Algorithm: Kyber-768
echo echo.
echo timeout /t 20 /nobreak
echo docker run -it --rm --name pqc-vpn-bob ^
echo   --cap-add=NET_ADMIN ^
echo   --device=/dev/net/tun ^
echo   -v "%DEMO_DIR%\client-bob":/etc/ipsec.d ^
echo   pqc-vpn:latest ^
echo   /bin/bash -c "ipsec start --nofork"
echo pause
) > "%DEMO_DIR%\start-bob.bat"

:: Charlie launcher  
(
echo @echo off
echo title PQC-VPN Client - Charlie ^(Hybrid^)
echo cd /d "%DEMO_DIR%\client-charlie"
echo echo Starting Charlie - Hybrid Authentication with Kyber-512...
echo echo.
echo echo %GREEN%🧑 Charlie Configuration:%NC%
echo echo   • IP: 10.10.1.52
echo echo   • Auth: Hybrid ^(PKI + PSK^)
echo echo   • Algorithm: Kyber-512
echo echo.
echo timeout /t 25 /nobreak
echo docker run -it --rm --name pqc-vpn-charlie ^
echo   --cap-add=NET_ADMIN ^
echo   --device=/dev/net/tun ^
echo   -v "%DEMO_DIR%\client-charlie":/etc/ipsec.d ^
echo   pqc-vpn:latest ^
echo   /bin/bash -c "ipsec start --nofork"
echo pause
) > "%DEMO_DIR%\start-charlie.bat"

:: Dashboard launcher
(
echo @echo off
echo title PQC-VPN Dashboard
echo cd /d "%BASE_DIR%\web"
echo echo Starting PQC-VPN Real-Time Dashboard...
echo echo.
echo echo %GREEN%📊 Dashboard Features:%NC%
echo echo   • Real-time connection monitoring
echo echo   • Live system metrics
echo echo   • PQC algorithm usage tracking
echo echo   • Interactive user management
echo echo.
echo echo %YELLOW%🔑 Dashboard Access:%NC%
echo echo   • URL: https://localhost:8443
echo echo   • Username: admin
echo echo   • Password: pqc-admin-2025
echo echo.
echo timeout /t 5 /nobreak
echo python api_server.py
echo pause
) > "%DEMO_DIR%\start-dashboard.bat"

:: Demo runner script
(
echo @echo off
echo setlocal
echo title PQC-VPN Demo Launcher
echo echo %BLUE%🔐 PQC-VPN Demo Launcher%NC%
echo echo ========================
echo echo.
echo echo Select component to start:
echo echo.
echo echo 1^) Hub Server ^(start first^)
echo echo 2^) Alice Client ^(PKI + Kyber-1024^)
echo echo 3^) Bob Client ^(PSK + Kyber-768^)
echo echo 4^) Charlie Client ^(Hybrid + Kyber-512^)
echo echo 5^) Dashboard ^(Real-time monitoring^)
echo echo 6^) Start All ^(automatic sequence^)
echo echo 7^) Exit
echo echo.
echo set /p choice="Enter choice [1-7]: "
echo.
echo if "!choice!"=="1" start cmd /k "%DEMO_DIR%\start-hub.bat"
echo if "!choice!"=="2" start cmd /k "%DEMO_DIR%\start-alice.bat"
echo if "!choice!"=="3" start cmd /k "%DEMO_DIR%\start-bob.bat"
echo if "!choice!"=="4" start cmd /k "%DEMO_DIR%\start-charlie.bat"
echo if "!choice!"=="5" start cmd /k "%DEMO_DIR%\start-dashboard.bat"
echo if "!choice!"=="6" goto start_all
echo if "!choice!"=="7" exit /b 0
echo.
echo goto menu
echo.
echo :start_all
echo echo %GREEN%🚀 Starting complete demo sequence...%NC%
echo echo.
echo echo 1. Starting Hub Server...
echo start cmd /k "%DEMO_DIR%\start-hub.bat"
echo timeout /t 5 /nobreak
echo.
echo echo 2. Starting Dashboard...
echo start cmd /k "%DEMO_DIR%\start-dashboard.bat"
echo timeout /t 3 /nobreak
echo.
echo echo 3. Starting Alice...
echo start cmd /k "%DEMO_DIR%\start-alice.bat"
echo timeout /t 3 /nobreak
echo.
echo echo 4. Starting Bob...
echo start cmd /k "%DEMO_DIR%\start-bob.bat"
echo timeout /t 3 /nobreak
echo.
echo echo 5. Starting Charlie...
echo start cmd /k "%DEMO_DIR%\start-charlie.bat"
echo.
echo echo %GREEN%✅ All components started!%NC%
echo echo.
echo echo %YELLOW%📊 Access Dashboard: https://localhost:8443%NC%
echo echo %YELLOW%🔑 Login: admin / pqc-admin-2025%NC%
echo echo.
echo pause
echo exit /b 0
echo.
echo :menu
) > "%DEMO_DIR%\run-demo.bat"

:: Create README for demo
(
echo # PQC-VPN Windows Demo
echo.
echo This directory contains a complete demo setup for PQC-VPN with:
echo.
echo ## Components
echo - **Hub Server**: Central VPN server ^(10.10.0.1^)
echo - **Alice**: PKI authentication with Kyber-1024 ^(10.10.1.50^)
echo - **Bob**: PSK authentication with Kyber-768 ^(10.10.1.51^)
echo - **Charlie**: Hybrid authentication with Kyber-512 ^(10.10.1.52^)
echo - **Dashboard**: Real-time monitoring interface
echo.
echo ## Quick Start
echo 1. Run `run-demo.bat` to launch the demo menu
echo 2. Choose option 6 to start all components automatically
echo 3. Access dashboard at: https://localhost:8443
echo 4. Login with: admin / pqc-admin-2025
echo.
echo ## Manual Start
echo 1. `start-hub.bat` - Start hub server first
echo 2. `start-alice.bat` - Start Alice client
echo 3. `start-bob.bat` - Start Bob client  
echo 4. `start-charlie.bat` - Start Charlie client
echo 5. `start-dashboard.bat` - Start monitoring dashboard
echo.
echo ## Testing
echo Once all components are running, the dashboard will show:
echo - 3 active connections
echo - Different PQC algorithms in use
echo - Real-time system metrics
echo - Live connection management
echo.
echo ## Troubleshooting
echo - Ensure Docker Desktop is running
echo - Check that ports 500, 4500, 8443 are available
echo - Run PowerShell/cmd as Administrator
echo - Verify Python and pip are installed
) > "%DEMO_DIR%\README.md"

echo.
echo %GREEN%✅ Demo setup complete!%NC%
echo.
echo %YELLOW%📁 Demo files created in: %DEMO_DIR%%NC%
echo.
echo %BLUE%🚀 To start the demo:%NC%
echo   1. cd "%DEMO_DIR%"
echo   2. run-demo.bat
echo.
echo %BLUE%📊 Dashboard access:%NC%
echo   • URL: https://localhost:8443
echo   • Login: admin / pqc-admin-2025
echo.

:: Ask if user wants to start demo now
set /p start_now="Start demo now? (y/N): "
if /i "!start_now!"=="y" (
    cd "%DEMO_DIR%"
    start cmd /k "run-demo.bat"
)

echo.
echo %GREEN%Demo setup completed successfully!%NC%
pause
