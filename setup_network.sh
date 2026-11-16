#!/bin/bash
# setup_network.sh — recreate all namespaces and veth pairs
# Run once after reboot: sudo bash setup_network.sh

set -e
echo "[*] Setting up 5G SCADA simulation network..."

# --- Clean up any existing state ---
ip netns del mtu_server 2>/dev/null || true
ip netns del ue_rtu     2>/dev/null || true
ip netns del attacker   2>/dev/null || true
ip link del br-5g       2>/dev/null || true

# --- Create namespaces ---
ip netns add mtu_server
ip netns add ue_rtu
ip netns add attacker
echo "[+] Namespaces created"

# --- Create bridge ---
ip link add br-5g type bridge
ip link set br-5g up
echo "[+] Bridge br-5g created"

# --- MTU veth pair ---
ip link add veth-mtu    type veth peer name veth-mtu-br
ip link set veth-mtu    netns mtu_server
ip link set veth-mtu-br master br-5g
ip link set veth-mtu-br up
ip netns exec mtu_server ip link set veth-mtu up
ip netns exec mtu_server ip addr add 10.45.0.1/24 dev veth-mtu
ip netns exec mtu_server ip link set lo up
echo "[+] MTU veth configured: 10.45.0.1"

# --- RTU veth pair ---
ip link add veth-rtu    type veth peer name veth-rtu-br
ip link set veth-rtu    netns ue_rtu
ip link set veth-rtu-br master br-5g
ip link set veth-rtu-br up
ip netns exec ue_rtu ip link set veth-rtu up
ip netns exec ue_rtu ip addr add 10.45.0.2/24 dev veth-rtu
ip netns exec ue_rtu ip link set lo up
echo "[+] RTU veth configured: 10.45.0.2"

# --- Attacker veth pair ---
ip link add veth-atk    type veth peer name veth-atk-br
ip link set veth-atk    netns attacker
ip link set veth-atk-br master br-5g
ip link set veth-atk-br up
ip netns exec attacker ip link set veth-atk up
ip netns exec attacker ip addr add 10.45.0.99/24 dev veth-atk
ip netns exec attacker ip link set lo up
echo "[+] Attacker veth configured: 10.45.0.99"

# --- Verify ---
echo ""
echo "[*] Verifying connectivity..."
ip netns exec mtu_server ping -c 2 -W 1 10.45.0.2 && echo "[+] MTU -> RTU OK" || echo "[!] MTU -> RTU FAILED"
ip netns exec attacker   ping -c 2 -W 1 10.45.0.2 && echo "[+] ATK -> RTU OK" || echo "[!] ATK -> RTU FAILED"

echo ""
echo "[*] Network ready. Run:"
echo "    sudo ip netns exec ue_rtu     python3 ~/5g-thesis-lab/rtu_substation.py"
echo "    sudo ip netns exec mtu_server python3 ~/5g-thesis-lab/mtu.py --mode open"
echo "    sudo ip netns exec attacker   python3 ~/5g-thesis-lab/attacker.py"

# --- Start UPF ---
echo "[*] Starting Open5GS UPF..."
docker start 5g-core 2>/dev/null || true
sleep 2
docker exec -d 5g-core /install/bin/open5gs-upfd -c /install/etc/open5gs/upf.yaml
sleep 1
docker exec 5g-core ps aux | grep upfd | grep -v grep && echo "[+] UPF running" || echo "[!] UPF failed to start"
