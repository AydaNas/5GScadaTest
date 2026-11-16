"""
rtu_substation.py — IEC 60870-5-104 RTU simulator

HOW TO RUN:
  Scenario A (no auth):  sudo ip netns exec ue_rtu python3 rtu_substation.py
  Scenario B (secure):   sudo ip netns exec ue_rtu python3 rtu_substation.py --secure
"""

import socket, hmac, hashlib, argparse, logging, time

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [RTU] %(levelname)s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger("RTU")

BIND_IP    = "10.45.0.2"
PORT       = 2404
SECRET     = b"SCADA_TESTBED_KEY_2024"   # must match mtu.py
SIG_TAG    = b"|SIG|"
PDCP_DELAY = 0.0005   # 0.5ms from 3GPP TR 38.824 — emulated, not measured

STARTDT_CON = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
TESTFR_CON  = bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00])


def recv_exactly(conn, n):
    """Read exactly n bytes from a TCP socket (TCP may deliver less in one call)."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def build_s_frame(recv_sn):
    """S-frame = acknowledgement sent back to MTU after each valid I-frame."""
    return bytes([0x68, 0x04, 0x01, 0x00,
                  (recv_sn << 1) & 0xFF, (recv_sn >> 7) & 0xFF])


def verify_sig(asdu, sig):
    """Return True if sig is a valid HMAC-SHA256 of asdu using SECRET."""
    expected = hmac.new(SECRET, asdu, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig)


def extract_asdu_and_sig(payload):
    """
    Split payload into (asdu, signature) at the |SIG| tag.
    Returns (None, None) if no tag is found.
    Uses find() not split() — safe even if tag bytes appear in the data.
    """
    pos = payload.find(SIG_TAG)
    if pos == -1:
        return None, None
    return payload[:pos], payload[pos + len(SIG_TAG) : pos + len(SIG_TAG) + 32]


def handle(conn, addr, secure):
    log.info(f"Connection from {addr[0]}")
    recv_sn, started = 0, False
    try:
        while True:
            header = recv_exactly(conn, 6)
            if not header:
                break

            if header[0] != 0x68:
                continue

            frame_type = ('I' if (header[2] & 1) == 0 else
                          'S' if (header[2] & 3) == 1 else 'U')

            if frame_type == 'U':
                if header[2] == 0x07:                  # STARTDT ACT
                    conn.sendall(STARTDT_CON)
                    started = True
                    log.info("STARTDT — ready")
                elif header[2] == 0x43:                # TESTFR ACT
                    conn.sendall(TESTFR_CON)
                continue

            if not started or frame_type != 'I':
                continue

            payload = recv_exactly(conn, header[1] - 4)
            if not payload:
                break

            asdu, sig = extract_asdu_and_sig(payload)

            if secure:
                if asdu is None:
                    log.warning("[SECURE] ✗ REJECTED — no signature (injection?)")
                    continue
                time.sleep(PDCP_DELAY)   # emulate PDCP processing time (TR 38.824)
                if verify_sig(asdu, sig):
                    log.info(f"[SECURE] ✓ accepted | {asdu.hex()}")
                    recv_sn += 1
                    conn.sendall(build_s_frame(recv_sn))
                else:
                    log.warning("[SECURE] ✗ REJECTED — bad signature (injection?)")
            else:
                display = asdu if asdu else payload
                log.info(f"[OPEN] ← accepted (no auth) | {display.hex()}")
                recv_sn += 1
                conn.sendall(build_s_frame(recv_sn))

    except (ConnectionResetError, ConnectionError):
        pass
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--secure", action="store_true",
                        help="Enable HMAC signature verification (Scenario B)")
    args = parser.parse_args()

    mode = "SECURE (HMAC + PDCP emulation)" if args.secure else "OPEN (no auth)"
    log.info(f"RTU listening on {BIND_IP}:{PORT} — {mode}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_IP, PORT))
    srv.listen(5)

    try:
        while True:
            conn, addr = srv.accept()
            handle(conn, addr, args.secure)
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
