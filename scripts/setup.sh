#!/bin/bash
# setup.sh: Configuration and variable setup for ChainRecon

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./main.sh)${NC}"
  exit
fi

setup_variables() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}          CONFIGURATION PHASE           ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    echo -e "${GREEN}[+] Output will be saved to: $OUTPUT_DIR${NC}"
    echo ""
    
    # Show current network info to help user
    echo -e "${YELLOW}[i] Current network configuration:${NC}"
    echo "-------------------------------------"
    ip -br addr show 2>/dev/null | head -10
    echo "-------------------------------------"
    echo ""
    
    # Prompt for Router IP (connected to IoT device)
    echo -e "${YELLOW}[?] ROUTER IP ADDRESS${NC}"
    echo -e "    ${BLUE}Explanation:${NC}"
    echo "      - This is the IP of the physical router connected to your IoT device"
    echo "      - The router forwards IoT traffic through your machine"
    echo "      - Usually something like 192.168.1.1 or 192.168.123.1"
    echo -e "    ${BLUE}How to find:${NC}"
    echo "      - Check router's admin page or label on the device"
    echo "      - After network setup, it should be in the same subnet as your Ethernet IP"
    echo ""
    read -p "Enter Router IP (e.g., 192.168.123.1): " ROUTER_IP
    
    # Validate IP format
    if [[ ! $ROUTER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${YELLOW}[!] Warning: '$ROUTER_IP' doesn't look like a valid IP. Proceeding anyway...${NC}"
    fi
    echo ""
    
    # Prompt for IoT Device IP
    echo -e "${YELLOW}[?] IOT DEVICE IP ADDRESS${NC}"
    echo -e "    ${BLUE}Explanation:${NC}"
    echo "      - This is the IP address of the IoT device you want to analyze"
    echo "      - The device should be connected to the router you specified above"
    echo -e "    ${BLUE}How to find:${NC}"
    echo "      - Check router's DHCP client list"
    echo "      - Use nmap to scan the router's subnet: nmap -sn 192.168.123.0/24"
    echo "      - Check the IoT device's app or settings"
    echo ""
    read -p "Enter IoT Device IP (leave blank to scan later): " TARGET_IP
    
    if [[ -n "$TARGET_IP" ]] && [[ ! $TARGET_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${YELLOW}[!] Warning: '$TARGET_IP' doesn't look like a valid IP.${NC}"
    fi
    echo ""
    
    # Prompt for Interface (optional at this stage)
    echo -e "${YELLOW}[?] CAPTURE INTERFACE (optional)${NC}"
    echo -e "    ${BLUE}Note:${NC} You can configure this later in Network Setup (Option 1)"
    echo ""
    read -p "Enter interface for traffic capture (or press Enter to skip): " INTERFACE
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Configuration Summary:${NC}"
    echo "  Router IP:      ${ROUTER_IP:-Not set}"
    echo "  IoT Device IP:  ${TARGET_IP:-Not set (will scan later)}"
    echo "  Interface:      ${INTERFACE:-Not set (configure in Network Setup)}"
    echo "  Output Dir:     $OUTPUT_DIR"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}
