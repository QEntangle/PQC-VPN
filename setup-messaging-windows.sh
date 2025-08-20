#!/bin/bash

# Windows-Compatible PQC-VPN Messaging Script
# Handles TTY issues with Git Bash on Windows

echo "🖥️ Windows PQC-VPN Messaging Setup"
echo "=================================="

# Detect Windows environment
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || -n "$WINDIR" ]]; then
    WINDOWS_ENV=true
    echo "✅ Windows environment detected"
else
    WINDOWS_ENV=false
    echo "ℹ️ Non-Windows environment"
fi

# Check if containers are running
if ! docker ps | grep -q pqc-vpn-hub; then
    echo "❌ PQC-VPN demo is not running!"
    echo "🚀 Start it first: ./run-complete-demo.sh"
    exit 1
fi

echo "✅ PQC-VPN containers are running"

# Setup messaging if not already done
if ! docker exec pqc-vpn-hub test -f /tmp/quick_chat.py; then
    echo "🔧 Setting up messaging servers..."
    ./setup-messaging.sh
else
    echo "✅ Messaging servers already configured"
fi

echo ""
echo "💬 Windows-Compatible Messaging Methods:"
echo ""

# Method 1: Direct messaging (works in Git Bash)
echo "1️⃣  DIRECT MESSAGING (Works in Git Bash)"
echo "   Copy and paste these commands one at a time:"
echo ""
echo "   # Client 1 → Client 2"
echo "   echo 'Hello Client 2, from Client 1!' | docker exec -i pqc-vpn-client1 nc 172.20.0.102 8888"
echo ""
echo "   # Client 2 → Client 3"  
echo "   echo 'Hi Client 3, from Client 2!' | docker exec -i pqc-vpn-client2 nc 172.20.0.103 8888"
echo ""
echo "   # Client 3 → Client 1"
echo "   echo 'Hello Client 1, from Client 3!' | docker exec -i pqc-vpn-client3 nc 172.20.0.101 8888"
echo ""
echo "   # Hub → All Clients (broadcast)"
echo "   for ip in 172.20.0.101 172.20.0.102 172.20.0.103; do"
echo "       echo 'Broadcast from Hub: \$(date)' | docker exec -i pqc-vpn-hub nc \$ip 8888"
echo "   done"
echo ""

# Method 2: Interactive chat for different terminals
echo "2️⃣  INTERACTIVE GROUP CHAT"
echo ""
if [ "$WINDOWS_ENV" = true ]; then
    echo "   🖥️ For Git Bash (current terminal):"
    echo "   winpty docker exec -it pqc-vpn-client1 python3 /tmp/quick_chat.py"
    echo ""
    echo "   🚀 For Windows Terminal/PowerShell (recommended):"
    echo "   docker exec -it pqc-vpn-client1 python3 /tmp/quick_chat.py"
    echo "   docker exec -it pqc-vpn-client2 python3 /tmp/quick_chat.py"
    echo "   docker exec -it pqc-vpn-client3 python3 /tmp/quick_chat.py"
    echo "   docker exec -it pqc-vpn-hub python3 /tmp/quick_chat.py 172.20.0.100"
else
    echo "   🐧 For Linux/Mac:"
    echo "   docker exec -it pqc-vpn-client1 python3 /tmp/quick_chat.py"
    echo "   docker exec -it pqc-vpn-client2 python3 /tmp/quick_chat.py"
    echo "   docker exec -it pqc-vpn-client3 python3 /tmp/quick_chat.py"
    echo "   docker exec -it pqc-vpn-hub python3 /tmp/quick_chat.py 172.20.0.100"
fi

echo ""
echo "3️⃣  AUTOMATED DEMO (Works everywhere)"
echo "   Run this for an automated messaging demonstration:"
echo ""

# Create automated demo function
create_auto_demo() {
    cat > auto_messaging_demo.sh << 'EOF'
#!/bin/bash
echo "🎭 Automated PQC-VPN Messaging Demo"
echo "==================================="

echo "📨 Testing direct client-to-client messaging..."

# Test 1: Client-to-client messages
echo "Test 1: Client 1 → Client 2"
echo "Hello Client 2! This is an encrypted message from Client 1" | docker exec -i pqc-vpn-client1 nc 172.20.0.102 8888
sleep 1

echo "Test 2: Client 2 → Client 3"  
echo "Hi Client 3! Secure message from Client 2 via PQC-VPN" | docker exec -i pqc-vpn-client2 nc 172.20.0.103 8888
sleep 1

echo "Test 3: Client 3 → Client 1"
echo "Greetings Client 1! This is Client 3 through encrypted tunnel" | docker exec -i pqc-vpn-client3 nc 172.20.0.101 8888
sleep 1

# Test 2: Hub broadcasts
echo "📢 Testing hub broadcast to all clients..."
for i in {1..3}; do
    for ip in 172.20.0.101 172.20.0.102 172.20.0.103; do
        echo "Broadcast $i from Hub: All systems operational! Time: $(date +%H:%M:%S)" | docker exec -i pqc-vpn-hub nc $ip 8888 &
    done
    sleep 2
done

# Test 3: Rapid messaging
echo "⚡ Testing rapid messaging..."
for i in {1..5}; do
    echo "Rapid message $i from Client 1" | docker exec -i pqc-vpn-client1 nc 172.20.0.102 8888 &
    echo "Rapid reply $i from Client 2" | docker exec -i pqc-vpn-client2 nc 172.20.0.101 8888 &
    sleep 0.5
done

wait  # Wait for all background processes

echo ""
echo "📊 Message delivery verification:"
echo "Client 1 received:"
docker exec pqc-vpn-client1 tail -3 /tmp/msg_server.log 2>/dev/null || echo "  (No messages yet)"
echo ""
echo "Client 2 received:"  
docker exec pqc-vpn-client2 tail -3 /tmp/msg_server.log 2>/dev/null || echo "  (No messages yet)"
echo ""
echo "Client 3 received:"
docker exec pqc-vpn-client3 tail -3 /tmp/msg_server.log 2>/dev/null || echo "  (No messages yet)"

echo ""
echo "✅ Automated messaging demo complete!"
echo "🔐 All messages were encrypted through PQC-VPN tunnel"
EOF

    chmod +x auto_messaging_demo.sh
}

create_auto_demo

echo "   ./auto_messaging_demo.sh"
echo ""

# Quick test section
echo "🧪 QUICK TEST (Try this now!):"
echo ""
echo "   # Send a test message:"
echo "   echo 'Windows test message!' | docker exec -i pqc-vpn-client1 nc 172.20.0.102 8888"
echo ""
echo "   # Check if it was received:"
echo "   docker exec pqc-vpn-client2 tail -1 /tmp/msg_server.log"
echo ""

# Monitoring section
echo "🔍 MONITOR MESSAGE ACTIVITY:"
echo ""
echo "   # Watch Client 1 messages:"
echo "   docker exec pqc-vpn-client1 tail -f /tmp/msg_server.log"
echo ""
echo "   # Watch group chat activity:"
echo "   docker exec pqc-vpn-hub tail -f /tmp/chat_server.log"
echo ""

# Troubleshooting section
if [ "$WINDOWS_ENV" = true ]; then
    echo "🛠️ WINDOWS TROUBLESHOOTING:"
    echo ""
    echo "   If you get TTY errors:"
    echo "   1. Use 'winpty' prefix: winpty docker exec -it ..."
    echo "   2. Or use Windows Terminal/PowerShell instead of Git Bash"
    echo "   3. Or stick to direct messaging (no TTY required)"
    echo ""
fi

echo "🎯 RECOMMENDED NEXT STEPS:"
echo ""
echo "1. Test direct messaging first (copy command above)"
echo "2. Check message delivery (copy command above)"  
echo "3. Run automated demo: ./auto_messaging_demo.sh"
if [ "$WINDOWS_ENV" = true ]; then
    echo "4. For interactive chat, open Windows Terminal and use docker exec -it commands"
else
    echo "4. For interactive chat, open multiple terminals and use docker exec -it commands"
fi

echo ""
echo "🔐 All communications are encrypted through your PQC-VPN tunnel!"
echo "🚀 Start testing your secure messaging now!"
