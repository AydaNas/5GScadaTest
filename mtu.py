"""
mtu.py — IEC 60870-5-104 MTU benchmark

HOW TO RUN:
  Scenario A:    sudo ip netns exec mtu_server python3 mtu.py --mode open
  Scenario B:    sudo ip netns exec mtu_server python3 mtu.py --mode secure
  Both:          sudo ip netns exec mtu_server python3 mtu.py --mode both

Start rtu_substation.py first, then run this.
"""

import socket, struct, hmac, hashlib, time, statistics, argparse, logging

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [MTU] %(levelname)s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger("MTU")

RTU_IP  = "10.45.0.2"
PORT    = 2404
SECRET  = b"SCADA_TESTBED_KEY_2024"   # must match rtu_substation.py
SIG_TAG = b"|SIG|"

WARMUP_FRAMES  = 50
MEASURE_FRAMES = 1000
FRAME_GAP      = 0.01   # 10ms between frames — gives attacker time to observe

STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])


def recv_exactly(sock, n):
    """Read exactly n bytes — TCP may deliver less than n in a single recv() call."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def build_i_frame(send_sn, asdu):
    """Wrap ASDU in a 6-byte IEC 104 I-frame header with sequence numbers."""
    cf = bytes([(send_sn << 1) & 0xFF, (send_sn >> 7) & 0xFF, 0x00, 0x00])
    return bytes([0x68, 4 + len(asdu)]) + cf + asdu


def build_asdu(value):
    """
    Build a C_SC_NA_1 (single command) ASDU — Type 0x2D, IOA=1.
    value=0 means OFF/CLOSE, value=1 means ON/OPEN.
    This is the same command type used in the Industroyer attack (Ukraine 2016).
    """
    return bytes([0x2D, 0x01, 0x06, 0x01]) + struct.pack('<I', 1)[:3] + bytes([value])


def sign_asdu(asdu):
    """Append HMAC-SHA256 signature: <asdu> |SIG| <32 bytes>"""
    return asdu + SIG_TAG + hmac.new(SECRET, asdu, hashlib.sha256).digest()


def run_scenario(label, use_integrity):
    log.info(f"--- {label} ---")
    rtt_list, crypto_list, timeouts = [], [], 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((RTU_IP, PORT))
        sock.settimeout(2)
        sock.sendall(STARTDT_ACT)
        if recv_exactly(sock, 6) != bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]):
            raise RuntimeError("STARTDT failed")
        log.info("Connected and STARTDT handshake complete")
    except Exception as e:
        log.error(f"Cannot connect: {e}")
        return None

    for i in range(WARMUP_FRAMES + MEASURE_FRAMES):
        asdu = build_asdu(i % 2)

        if use_integrity:
            t0 = time.perf_counter()
            payload = sign_asdu(asdu)
            crypto_ms = (time.perf_counter() - t0) * 1000
        else:
            payload, crypto_ms = asdu, 0.0

        t_send = time.perf_counter()
        sock.sendall(build_i_frame(i % 32768, payload))

        try:
            recv_exactly(sock, 6)   # wait for S-frame acknowledgement
            rtt_ms = (time.perf_counter() - t_send) * 1000
            if i >= WARMUP_FRAMES:
                rtt_list.append(rtt_ms)
                if use_integrity:
                    crypto_list.append(crypto_ms)
        except socket.timeout:
            timeouts += 1

        time.sleep(FRAME_GAP)

    sock.close()

    if not rtt_list:
        log.error("No results collected")
        return None

    return {
        "label":  label,
        "avg":    statistics.mean(rtt_list),
        "median": statistics.median(rtt_list),
        "jitter": statistics.stdev(rtt_list),
        "min":    min(rtt_list),
        "max":    max(rtt_list),
        "loss":   timeouts / (WARMUP_FRAMES + MEASURE_FRAMES) * 100,
        "crypto": statistics.mean(crypto_list) if crypto_list else 0.0,
    }


def print_table(a, b):
    overhead_ms  = b["avg"] - a["avg"]
    overhead_pct = overhead_ms / a["avg"] * 100

    print("\n" + "=" * 56)
    print("  IEC 60870-5-104 APPLICATION-LAYER SECURITY OVERHEAD")
    print("  Software testbed — motivated by 3GPP TS 33.501 UPIP")
    print("=" * 56)
    print(f"  {'Metric':<26} {'Scenario A':>12} {'Scenario B':>12}")
    print(f"  {'':26} {'(no HMAC)':>12} {'(HMAC ON)':>12}")
    print("-" * 56)
    for key, label in [("avg","Mean RTT (ms)"), ("median","Median RTT (ms)"),
                       ("jitter","Jitter (ms)"), ("min","Min (ms)"),
                       ("max","Max (ms)"), ("loss","Loss (%)")]:
        print(f"  {label:<26} {a[key]:>12.4f} {b[key]:>12.4f}")
    print("-" * 56)
    print(f"  {'Crypto OH (MEASURED ms)':<26} {'N/A':>12} {b['crypto']:>12.4f}")
    print(f"  {'PDCP delay (EMULATED ms)':<26} {'0.0000':>12} {'0.5000':>12}")
    print(f"  {'Total overhead (ms)':<26} {overhead_ms:>24.4f}")
    print(f"  {'Overhead (%)':<26} {overhead_pct:>23.2f}%")
    print("=" * 56)
    print()
    print("  NOTE: The 0.5ms PDCP figure is a reference value from 3GPP TR 38.824,")
    print("  emulated with time.sleep(). Only the crypto overhead is a real measurement.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["open","secure","both"], default="both")
    args = parser.parse_args()

    a = run_scenario("Scenario A — No integrity protection", False) if args.mode in ("open","both") else None
    b = run_scenario("Scenario B — HMAC integrity protection", True) if args.mode in ("secure","both") else None

    if a and b:
        print_table(a, b)
    elif a:
        log.info(f"Done — avg RTT {a['avg']:.4f}ms")
    elif b:
        log.info(f"Done — avg RTT {b['avg']:.4f}ms  crypto {b['crypto']:.4f}ms")


if __name__ == "__main__":
    main()
