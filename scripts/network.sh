#!/bin/bash
# network.sh: Network setup for ChainRecon

network_setup() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}       PHYSICAL SETUP INSTRUCTIONS       ${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    echo -e "${BLUE}Setup Overview:${NC}"
    echo "  1. Connect the IoT device to a physical router"
    echo "  2. Connect that router to this computer via Ethernet"
    echo "  3. Forward traffic from Ethernet → WiFi (for IoT internet access)"
    echo "  4. This allows us to capture all IoT traffic (IPs, domains, protocols)"
    echo ""
    echo -e "${YELLOW}[i] Detecting available network interfaces...${NC}"
    echo ""
    
    # List available interfaces for user reference
    echo -e "${GREEN}Available interfaces:${NC}"
    echo "-------------------------------------"
    ip -br link show | while read line; do
        iface=$(echo "$line" | awk '{print $1}')
        state=$(echo "$line" | awk '{print $2}')
        echo -e "  ${BLUE}$iface${NC} - State: $state"
    done
    echo "-------------------------------------"
    echo ""
    
    # Show interfaces with more detail (IP addresses if assigned)
    echo -e "${GREEN}Interface details (with IPs if assigned):${NC}"
    ip -br addr show
    echo ""
    
    # Prompt for Ethernet interface (connected to router with IoT device)
    echo -e "${YELLOW}[?] ETHERNET INTERFACE (connected to router with IoT device)${NC}"
    echo -e "    ${BLUE}How to identify:${NC}"
    echo "      - USB Ethernet adapters often start with 'enx' followed by MAC address"
    echo "      - Built-in Ethernet usually named 'eth0', 'enp0s...', or similar"
    echo "      - Look for an interface that appeared when you plugged in the Ethernet cable"
    echo ""
    read -p "Enter the Ethernet interface name (e.g., enx00051bdcce3e, eth0): " ETH_INTERFACE
    
    # Validate interface exists
    if ! ip link show "$ETH_INTERFACE" &> /dev/null; then
        echo -e "${RED}[!] Warning: Interface '$ETH_INTERFACE' not found. Proceeding anyway...${NC}"
    fi
    echo ""
    
    # Prompt for Internet/WiFi interface (has internet access)
    echo -e "${YELLOW}[?] INTERNET INTERFACE (with active internet connection, usually WiFi)${NC}"
    echo -e "    ${BLUE}How to identify:${NC}"
    echo "      - WiFi interfaces usually named 'wlan0', 'wlp...', 'wifi0', etc."
    echo "      - Check which interface has an IP address and internet access"
    echo "      - Run 'ip route' to see the default gateway interface"
    echo ""
    # Show default route for reference
    echo -e "${GREEN}Current default route:${NC}"
    ip route | grep default
    echo ""
    read -p "Enter the Internet/WiFi interface name (e.g., wlan0, wlp2s0): " INTERNET_INTERFACE
    
    if ! ip link show "$INTERNET_INTERFACE" &> /dev/null; then
        echo -e "${RED}[!] Warning: Interface '$INTERNET_INTERFACE' not found. Proceeding anyway...${NC}"
    fi
    echo ""
    
    # Prompt for static IP for Ethernet interface
    echo -e "${YELLOW}[?] STATIC IP ADDRESS for Ethernet interface${NC}"
    echo -e "    ${BLUE}Explanation:${NC}"
    echo "      - This IP will be assigned to your Ethernet interface"
    echo "      - It should be in the same subnet as the router (e.g., 192.168.123.x)"
    echo "      - The IoT device will use this IP as its gateway"
    echo "      - Default: 192.168.123.100/24"
    echo ""
    read -p "Enter static IP with subnet (default: 192.168.123.100/24): " STATIC_IP
    STATIC_IP=${STATIC_IP:-192.168.123.100/24}
    echo ""
    
    # Confirmation
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${GREEN}Configuration Summary:${NC}"
    echo "  Ethernet Interface (IoT side):  $ETH_INTERFACE"
    echo "  Internet Interface (WiFi):      $INTERNET_INTERFACE"
    echo "  Static IP for Ethernet:         $STATIC_IP"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    
    read -p "Do you want to apply this network configuration? (y/n): " confirm
    if [[ $confirm == "y" ]]; then
        echo ""
        echo -e "${BLUE}[*] Step 1/5: Bringing up Ethernet interface...${NC}"
        ip link set up dev "$ETH_INTERFACE"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}    [+] Interface $ETH_INTERFACE is UP${NC}"
        else
            echo -e "${RED}    [!] Failed to bring up $ETH_INTERFACE${NC}"
        fi
        
        echo -e "${BLUE}[*] Step 2/5: Assigning static IP to Ethernet interface...${NC}"
        # Remove any existing IP first to avoid duplicates
        ip addr flush dev "$ETH_INTERFACE" 2>/dev/null
        ip addr add "$STATIC_IP" dev "$ETH_INTERFACE"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}    [+] Assigned $STATIC_IP to $ETH_INTERFACE${NC}"
        else
            echo -e "${RED}    [!] Failed to assign IP (may already be assigned)${NC}"
        fi
        
        echo -e "${BLUE}[*] Step 3/5: Enabling IP Forwarding...${NC}"
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        echo -e "${GREEN}    [+] IP Forwarding enabled${NC}"
        
        echo -e "${BLUE}[*] Step 4/5: Configuring NAT (Masquerading) on $INTERNET_INTERFACE...${NC}"
        iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE
        echo -e "${GREEN}    [+] NAT Masquerading configured${NC}"
        
        echo -e "${BLUE}[*] Step 5/5: Configuring Docker iptables rules...${NC}"
        # Check if DOCKER-USER chain exists before adding rules
        if iptables -L DOCKER-USER &>/dev/null; then
            iptables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            iptables -I DOCKER-USER 2 -i "$ETH_INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT
            echo -e "${GREEN}    [+] Docker iptables rules configured${NC}"
        else
            echo -e "${YELLOW}    [i] DOCKER-USER chain not found (Docker not installed or not running)${NC}"
            echo -e "${YELLOW}    [i] Skipping Docker-specific rules${NC}"
        fi
        
        echo ""
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}[+] Network setup complete!${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo ""
        echo -e "${BLUE}[i] Your device is now acting as a router.${NC}"
        echo -e "${BLUE}[i] IoT devices can use ${STATIC_IP%/*} as their gateway.${NC}"
        echo -e "${BLUE}[i] Traffic will be forwarded: $ETH_INTERFACE → $INTERNET_INTERFACE${NC}"
        
        # Update the global INTERFACE variable to use the Ethernet interface for captures
        INTERFACE="$ETH_INTERFACE"
        echo ""
        echo -e "${YELLOW}[i] Note: INTERFACE variable updated to '$ETH_INTERFACE' for traffic capture.${NC}"
        
    else
        echo -e "${RED}[!] Skipping network configuration.${NC}"
    fi
    echo "-------------------------------------"
}