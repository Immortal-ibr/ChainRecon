#!/bin/bash
# Main controller for ChainRecon Bash scripts

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Global Variables
TARGET_IP=""
INTERFACE=""
OUTPUT_DIR="iot_recon_$(date +%Y%m%d_%H%M%S)"

# Source all mode scripts
SCRIPT_DIR="$(dirname "$0")"
. "$SCRIPT_DIR/setup.sh"
. "$SCRIPT_DIR/network.sh"
. "$SCRIPT_DIR/scan.sh"
. "$SCRIPT_DIR/capture.sh"
. "$SCRIPT_DIR/ssl.sh"

# --- MAIN MENU ---
clear
echo "=============================================="
echo "    IoT Research Recon Tool                   "
echo "=============================================="
setup_variables

while true; do
    echo "Select an operation mode:"
    echo "1) Network Setup (Enable Routing/NAT)"
    echo "2) Device Scan (Nmap - OS & Services)"
    echo "3) Traffic Capture (Tcpdump)"
    echo "4) SSL/Certificate Analysis"
    echo "5) Exit"
    read -p "Choice: " choice

    case $choice in
        1) network_setup ;;
        2) scan_device ;;
        3) capture_traffic ;;
        4) ssl_probe ;;
        5) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid option." ;;
    esac
    
    echo ""
    read -p "Press Enter to return to menu..."
done