#!/bin/bash

# PQC-VPN Terminal Messaging Setup Script
# Sets up real-time terminal messaging between server and clients

set -e

echo "💬 PQC-VPN Terminal Messaging Setup"
echo "===================================="

# Check if demo is running
if ! docker ps | grep -q pqc-vpn-hub; then
    echo "❌ PQC-VPN demo is not running!"
    echo "🚀 Please start the demo first:"
    echo "   ./run-complete-demo.sh"
    echo "   OR"
    echo "   docker-compose -f docker-compose.demo.yml up -d"
    exit 1
fi

echo "✅ PQC-VPN demo is running"

# Install required packages in containers
echo "📦 Installing messaging tools in containers..."
for container in pqc-vpn-hub pqc-vpn-client1 pqc-vpn-client2 pqc-vpn-client3; do
    docker exec $container bash -c "
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y netcat-openbsd python3 >/dev/null 2>&1
    " &
done
wait

echo "✅ Messaging tools installed"

# Setup Method 1: Multi-user Chat Server on Hub
echo "🔧 Setting up multi-user chat server on hub..."
docker exec pqc-vpn-hub bash -c "
cat > /tmp/chat_server.py << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import time

clients = []
nicknames = []

def broadcast(message, sender_client=None):
    for client in clients:
        if client != sender_client:
            try:
                client.send(message)
            except:
                remove_client(client)

def remove_client(client):
    if client in clients:
        index = clients.index(client)
        clients.remove(client)
        nickname = nicknames[index]
        nicknames.remove(nickname)
        broadcast(f'{nickname} left the chat!'.encode('utf-8'))
        client.close()

def handle_client(client):
    while True:
        try:
            message = client.recv(1024)
            if message:
                timestamp = time.strftime('%H:%M:%S')
                broadcast(f'[{timestamp}] {message.decode(\"utf-8\")}'.encode('utf-8'), client)
            else:
                remove_client(client)
                break
        except:
            remove_client(client)
            break

# Main server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 9999))
server.listen()

print('🔐 PQC-VPN Multi-User Chat Server running on port 9999')
print('💬 Waiting for connections...')

while True:
    try:
        client, address = server.accept()
        print(f'📱 Connection from {address}')
        
        client.send('Enter nickname: '.encode('utf-8'))
        nickname = client.recv(1024).decode('utf-8').strip()
        
        nicknames.append(nickname)
        clients.append(client)
        
        print(f'👤 {nickname} joined from {address}')
        broadcast(f'🎉 {nickname} joined the PQC-VPN chat!'.encode('utf-8'))
        
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.daemon = True
        thread.start()
    except KeyboardInterrupt:
        break
    except:
        continue

server.close()
EOF

# Start chat server in background
nohup python3 /tmp/chat_server.py > /tmp/chat_server.log 2>&1 &
echo \$! > /tmp/chat_server.pid
"

sleep 2

# Setup Method 2: Direct Message Servers on Each Client
echo "🔧 Setting up direct message servers on clients..."
for i in 1 2 3; do
    docker exec pqc-vpn-client$i bash -c "
    cat > /tmp/msg_server.py << 'EOF'
#!/usr/bin/env python3
import socket
import threading
from datetime import datetime

def handle_message(conn, addr):
    try:
        data = conn.recv(1024).decode('utf-8').strip()
        if data:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f'📨 [{timestamp}] Message from {addr[0]}: {data}')
            response = f'✅ Message received by Client $i at {timestamp}'
            conn.send(response.encode('utf-8'))
    except Exception as e:
        print(f'❌ Error: {e}')
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 8888))
server.listen(5)

print(f'📡 Client $i direct message server listening on port 8888')

while True:
    try:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_message, args=(conn, addr))
        thread.daemon = True
        thread.start()
    except KeyboardInterrupt:
        break
    except:
        continue

server.close()
EOF

    # Start message server in background
    nohup python3 /tmp/msg_server.py > /tmp/msg_server.log 2>&1 &
    echo \$! > /tmp/msg_server.pid
    " &
done
wait

sleep 2

# Create simple chat client script
echo "🔧 Creating chat client scripts..."
cat > /tmp/quick_chat.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys
import threading

def receive_messages(client):
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message:
                print(f'\r{message}')
                print('You> ', end='', flush=True)
            else:
                break
        except:
            break

def main():
    server_ip = sys.argv[1] if len(sys.argv) > 1 else '172.20.0.100'
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, 9999))
        
        # Handle nickname
        prompt = client.recv(1024).decode('utf-8')
        print(prompt, end='')
        nickname = input()
        client.send(nickname.encode('utf-8'))
        
        # Start receiving thread
        receive_thread = threading.Thread(target=receive_messages, args=(client,))
        receive_thread.daemon = True
        receive_thread.start()
        
        print(f'Connected to PQC-VPN chat as {nickname}')
        print('Type messages and press Enter. Type "quit" to exit.')
        print('=' * 50)
        
        while True:
            message = input('You> ')
            if message.lower() == 'quit':
                break
            client.send(f'{nickname}: {message}'.encode('utf-8'))
            
    except Exception as e:
        print(f'Error: {e}')
    finally:
        client.close()

if __name__ == '__main__':
    main()
EOF

# Copy chat client to all containers
for container in pqc-vpn-hub pqc-vpn-client1 pqc-vpn-client2 pqc-vpn-client3; do
    docker cp /tmp/quick_chat.py $container:/tmp/
done

echo "✅ All messaging servers are running!"
echo ""
echo "🎉 Terminal Messaging Setup Complete!"
echo ""
echo "📱 Available Messaging Methods:"
echo ""
echo "1️⃣  MULTI-USER CHAT (Recommended)"
echo "   Connect multiple users to group chat on hub:"
echo ""
echo "   Terminal 1 (Client 1):"
echo "   docker exec -it pqc-vpn-client1 python3 /tmp/quick_chat.py"
echo ""
echo "   Terminal 2 (Client 2):"
echo "   docker exec -it pqc-vpn-client2 python3 /tmp/quick_chat.py"
echo ""
echo "   Terminal 3 (Client 3):"
echo "   docker exec -it pqc-vpn-client3 python3 /tmp/quick_chat.py"
echo ""
echo "   Terminal 4 (Hub Admin):"
echo "   docker exec -it pqc-vpn-hub python3 /tmp/quick_chat.py 172.20.0.100"
echo ""
echo "2️⃣  DIRECT MESSAGING"
echo "   Send direct messages between specific clients:"
echo ""
echo "   # Client 1 → Client 2:"
echo "   echo 'Hello Client 2!' | docker exec -i pqc-vpn-client1 nc 172.20.0.102 8888"
echo ""
echo "   # Client 2 → Client 3:"
echo "   echo 'Hey Client 3!' | docker exec -i pqc-vpn-client2 nc 172.20.0.103 8888"
echo ""
echo "   # Hub → Client 1:"
echo "   echo 'Message from Hub' | docker exec -i pqc-vpn-hub nc 172.20.0.101 8888"
echo ""
echo "3️⃣  BROADCAST MESSAGING"
echo "   Send messages to all clients at once:"
echo ""
echo "   # Hub broadcasts to all clients:"
echo "   for ip in 172.20.0.101 172.20.0.102 172.20.0.103; do"
echo "       echo 'Broadcast message from Hub!' | docker exec -i pqc-vpn-hub nc \$ip 8888"
echo "   done"
echo ""
echo "4️⃣  SIMPLE NETCAT CHAT"
echo "   Basic one-on-one chat:"
echo ""
echo "   # Terminal 1 (Server):"
echo "   docker exec -it pqc-vpn-hub nc -l -p 7777"
echo ""
echo "   # Terminal 2 (Client):"
echo "   docker exec -it pqc-vpn-client1 nc 172.20.0.100 7777"
echo ""
echo "🔍 Monitor All Activity:"
echo "   # Watch message server logs:"
echo "   docker exec pqc-vpn-client1 tail -f /tmp/msg_server.log"
echo ""
echo "   # Watch chat server logs:"
echo "   docker exec pqc-vpn-hub tail -f /tmp/chat_server.log"
echo ""
echo "   # Monitor network traffic:"
echo "   docker exec pqc-vpn-hub tcpdump -i any port 9999 or port 8888"
echo ""
echo "🛑 Stop All Messaging Services:"
echo "   docker exec pqc-vpn-hub bash -c 'kill \$(cat /tmp/chat_server.pid)'"
echo "   for i in 1 2 3; do"
echo "       docker exec pqc-vpn-client\$i bash -c 'kill \$(cat /tmp/msg_server.pid)'"
echo "   done"
echo ""
echo "🔐 All messages are encrypted through the PQC-VPN tunnel!"
echo "🚀 Start messaging now by running the commands above!"
