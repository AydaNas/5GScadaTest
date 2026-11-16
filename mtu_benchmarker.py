import socket
import time
import hmac
import hashlib
import statistics

# --- CONFIGURATION ---
TARGET_IP = "10.45.0.2"  # IP of the ue_rtu (Substation)
PORT = 2404
SECRET_KEY = b"5G_SECURE_KEY_UKRAINE"
ITERATIONS = 100

def run_test(use_integrity):
    results = []
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    
    label = "ON" if use_integrity else "OFF"
    print(f"[*] Measuring Latency with 5G Integrity {label}...")

    for i in range(ITERATIONS):
        payload = f"COMMAND_VALVE_{i}".encode()
        
        # Start High-Precision Timer
        start = time.perf_counter()

        if use_integrity:
            # SCENARIO B: Emulate 5G User Plane Integrity (MAC-I math)
            signature = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
            packet = payload + b"|SIG|" + signature
        else:
            # SCENARIO A: Vulnerable "Dumb Pipe"
            packet = payload

        # Transmission
        sock.sendto(packet, (TARGET_IP, PORT))
        
        try:
            # Wait for ACK from Substation
            data, addr = sock.recvfrom(1024)
            # End High-Precision Timer
            end = time.perf_counter()
            results.append((end - start) * 1000) # Store in milliseconds
        except socket.timeout:
            continue

    sock.close()
    return statistics.mean(results)

if __name__ == "__main__":
    print("=== 5G SCADA PERFORMANCE BENCHMARK ===")
    
    # 1. Run Scenario A (The Baseline)
    avg_off = run_test(use_integrity=False)
    
    # 2. Run Scenario B (The Secure Version)
    avg_on = run_test(use_integrity=True)
    
    # --- FINAL CALCULATIONS FOR THESIS ---
    tax = avg_on - avg_off
    increase = (tax / avg_off) * 100

    print("\n" + "="*40)
    print(f"1. AVG LATENCY (OFF): {avg_off:.4f} ms")
    print(f"2. AVG LATENCY (ON):  {avg_on:.4f} ms")
    print(f"3. SECURITY TAX:      {tax:.4f} ms")
    print(f"4. OVERHEAD INCREASE: {increase:.2f} %")
    print("="*40)
    print("[TIP] Use these numbers for Table 1 in your report.")
