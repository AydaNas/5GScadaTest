import socket
import hmac, hashlib

# 5G Substation Config
IP = "10.45.0.2" 
PORT = 2404
KEY = b"5G_SECURE_KEY_UKRAINE"

# Create a UDP socket (standard for performance benchmarking)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP, PORT))

print(f"[*] Substation Kyiv-01 Online at {IP}:{PORT}")
print("[*] Smart Mode: Responding to both Secure and Open packets...")

while True:
    packet, addr = sock.recvfrom(1024)
    
    # Check if the packet has a signature tag
    if b"|SIG|" in packet:
        # Scenario B logic: Verify math
        try:
            data, received_sig = packet.split(b"|SIG|")
            expected_sig = hmac.new(KEY, data, hashlib.sha256).digest()
            if hmac.compare_digest(received_sig, expected_sig):
                sock.sendto(b"ACK_SECURE", addr)
        except Exception:
            pass
    else:
        # Scenario A logic: Just respond (Dumb Pipe mode)
        sock.sendto(b"ACK_OPEN", addr)
