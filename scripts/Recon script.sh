
#!/bin/bash

# ==========================================
# IOT SECURITY RECON AUTOMATION
# ==========================================
# This script automates network setup for MitM,
# port scanning, traffic capture, and SSL analysis.

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./iot_recon.sh)${NC}"
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

# --- MODE 1: PHYSICAL & NETWORK SETUP ---
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

# --- MODE 2: ACTIVE RECON (NMAP) ---
scan_device() {
    # Check if target IP is set
    if [[ -z "$TARGET_IP" ]]; then
        echo -e "${RED}[!] No target IP set. Please enter an IP address:${NC}"
        read -p "IoT Device IP: " TARGET_IP
    fi
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}         DEVICE SCANNING OPTIONS        ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${GREEN}Target: $TARGET_IP${NC}"
    echo ""
    echo "Select a scan mode:"
    echo ""
    echo "  1) Quick Scan       - Top 1000 ports, fast (-T4)"
    echo "                        Best for: Initial discovery"
    echo ""
    echo "  2) Gentle Scan      - Full TCP connect, slow (-T2)"
    echo "                        Best for: Fragile IoT devices that may crash"
    echo ""
    echo "  3) Full Scan        - All 65535 ports, aggressive detection (-A)"
    echo "                        Best for: Comprehensive audit (takes 5-15 min)"
    echo ""
    echo "  4) IoT Protocol     - UDP + IoT ports (UPnP, mDNS, CoAP, MQTT)"
    echo "                        Best for: IoT-specific service discovery"
    echo ""
    echo "  5) Vulnerability    - NSE vuln scripts + version detection"
    echo "                        Best for: Security assessment"
    echo ""
    echo "  6) Back to main menu"
    echo ""
    read -p "Choice [1-6]: " scan_choice
    
    case $scan_choice in
        1)
            echo -e "${BLUE}[*] Running Quick Scan...${NC}"
            echo -e "${YELLOW}[i] Scanning top 1000 ports with fast timing${NC}"
            nmap -Pn -sV -T4 --top-ports 1000 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap_quick.txt"
            echo -e "${GREEN}[+] Results saved to $OUTPUT_DIR/nmap_quick.txt${NC}"
            ;;
        2)
            echo -e "${BLUE}[*] Running Gentle Scan (IoT-safe)...${NC}"
            echo -e "${YELLOW}[i] Using TCP connect scan with polite timing to avoid crashing fragile devices${NC}"
            nmap -Pn -sT -sV -T2 --max-retries 1 -r "$TARGET_IP" -oN "$OUTPUT_DIR/nmap_gentle.txt"
            echo -e "${GREEN}[+] Results saved to $OUTPUT_DIR/nmap_gentle.txt${NC}"
            ;;
        3)
            echo -e "${BLUE}[*] Running Full Scan (comprehensive)...${NC}"
            echo -e "${YELLOW}[i] Scanning all 65535 ports with OS/version detection. This may take 5-15 minutes.${NC}"
            nmap -Pn -A -p- -T4 --version-intensity 9 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap_full.txt"
            echo -e "${GREEN}[+] Results saved to $OUTPUT_DIR/nmap_full.txt${NC}"
            ;;
        4)
            echo -e "${BLUE}[*] Running IoT Protocol Scan...${NC}"
            echo -e "${YELLOW}[i] Scanning common IoT ports (TCP + UDP)${NC}"
            echo ""
            echo "IoT Ports being scanned:"
            echo "  TCP: 80,443,8080,8443,8008,1883,8883 (HTTP/HTTPS/MQTT)"
            echo "  UDP: 53,67,123,1900,5353,5683 (DNS/DHCP/NTP/UPnP/mDNS/CoAP)"
            echo ""
            # TCP scan for common IoT ports
            nmap -Pn -sV -T4 -p 80,443,8080,8443,8008,1883,8883,502,102,47808 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap_iot_tcp.txt"
            # UDP scan for IoT protocols
            nmap -Pn -sU -T4 -p 53,67,123,1900,5353,5683 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap_iot_udp.txt"
            echo -e "${GREEN}[+] Results saved to $OUTPUT_DIR/nmap_iot_tcp.txt and nmap_iot_udp.txt${NC}"
            ;;
        5)
            echo -e "${BLUE}[*] Running Vulnerability Scan...${NC}"
            echo -e "${YELLOW}[i] Using NSE vulnerability scripts. This may take several minutes.${NC}"
            echo ""
            # Check if vulners script is available
            if nmap --script-help vulners &>/dev/null; then
                echo -e "${GREEN}[+] vulners.nse script found - will query vulnerability database${NC}"
                nmap -Pn -sV --script vulners,vuln -T4 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap_vuln.txt"
            else
                echo -e "${YELLOW}[i] vulners.nse not found - using built-in vuln scripts${NC}"
                echo -e "${BLUE}[i] Tip: Install vulners script for better CVE detection:${NC}"
                echo "    wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -O /usr/share/nmap/scripts/vulners.nse"
                echo ""
                nmap -Pn -sV --script vuln -T4 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap_vuln.txt"
            fi
            echo -e "${GREEN}[+] Results saved to $OUTPUT_DIR/nmap_vuln.txt${NC}"
            ;;
        6)
            return
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            return
            ;;
    esac
    echo "-------------------------------------"
}

# --- MODE 3: TRAFFIC INTERCEPTION ---
capture_traffic() {
    # Check if interface is set
    if [[ -z "$INTERFACE" ]]; then
        echo -e "${RED}[!] No interface set. Please configure in Network Setup first or enter now:${NC}"
        echo ""
        echo -e "${YELLOW}Available interfaces:${NC}"
        ip -br link show 2>/dev/null
        echo ""
        read -p "Enter interface name: " INTERFACE
    fi
    
    # Check if target IP is set
    if [[ -z "$TARGET_IP" ]]; then
        echo -e "${YELLOW}[i] No target IP set. Capture will include all traffic on interface.${NC}"
        read -p "Enter IoT Device IP (or press Enter for all traffic): " TARGET_IP
    fi
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}      TRAFFIC CAPTURE & ANALYSIS        ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${GREEN}Interface: $INTERFACE${NC}"
    echo -e "${GREEN}Target:    ${TARGET_IP:-All traffic}${NC}"
    echo ""
    echo "Select a capture mode:"
    echo ""
    echo "  1) Basic Capture      - tcpdump to pcap file"
    echo "                          Best for: Saving raw packets for Wireshark"
    echo ""
    echo "  2) Live Analysis      - tshark with real-time display"
    echo "                          Best for: Watching traffic in real-time"
    echo ""
    echo "  3) DNS Extraction     - Capture and extract all DNS queries/responses"
    echo "                          Best for: Finding domains IoT device contacts"
    echo ""
    echo "  4) HTTP Analysis      - Extract HTTP requests, URLs, and user-agents"
    echo "                          Best for: Finding unencrypted API calls"
    echo ""
    echo "  5) Protocol Stats     - Capture then analyze protocol distribution"
    echo "                          Best for: Understanding traffic patterns"
    echo ""
    echo "  6) Full Analysis      - Capture + DNS + HTTP + Stats (recommended)"
    echo "                          Best for: Complete traffic reconnaissance"
    echo ""
    echo "  7) Back to main menu"
    echo ""
    read -p "Choice [1-7]: " capture_choice
    
    # Get duration for capture
    if [[ $capture_choice != "7" ]]; then
        echo ""
        read -p "Enter duration to capture in seconds (default 60): " DURATION
        DURATION=${DURATION:-60}
        echo ""
        echo -e "${YELLOW}[i] Perform actions on the IoT device now!${NC}"
        echo "    (e.g., reboot it, talk to it, open the companion app)"
        echo ""
    fi
    
    # Build filter based on target IP
    if [[ -n "$TARGET_IP" ]]; then
        FILTER="host $TARGET_IP"
    else
        FILTER=""
    fi
    
    case $capture_choice in
        1)
            capture_basic
            ;;
        2)
            capture_live_tshark
            ;;
        3)
            capture_dns_extraction
            ;;
        4)
            capture_http_analysis
            ;;
        5)
            capture_protocol_stats
            ;;
        6)
            capture_full_analysis
            ;;
        7)
            return
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            return
            ;;
    esac
    echo "-------------------------------------"
}

# Sub-function: Basic tcpdump capture
capture_basic() {
    echo -e "${BLUE}[*] Starting basic packet capture (tcpdump)...${NC}"
    
    PCAP_FILE="$OUTPUT_DIR/traffic_$(date +%Y%m%d_%H%M%S).pcap"
    
    if [[ -n "$FILTER" ]]; then
        tcpdump -i "$INTERFACE" $FILTER -s 0 -w "$PCAP_FILE" &
    else
        tcpdump -i "$INTERFACE" -s 0 -w "$PCAP_FILE" &
    fi
    PID=$!
    
    echo -e "${GREEN}[+] Capturing for $DURATION seconds...${NC}"
    sleep "$DURATION"
    kill $PID 2>/dev/null
    
    echo -e "${GREEN}[+] Capture finished: $PCAP_FILE${NC}"
    echo -e "${BLUE}[i] Open with Wireshark for detailed analysis${NC}"
}

# Sub-function: Live tshark analysis
capture_live_tshark() {
    # Check if tshark is available
    if ! command -v tshark &>/dev/null; then
        echo -e "${RED}[!] tshark not found. Install with: apt install tshark${NC}"
        echo -e "${YELLOW}[i] Falling back to tcpdump...${NC}"
        capture_basic
        return
    fi
    
    echo -e "${BLUE}[*] Starting live traffic analysis (tshark)...${NC}"
    echo -e "${YELLOW}[i] Showing real-time packet summary. Press Ctrl+C to stop.${NC}"
    echo ""
    
    PCAP_FILE="$OUTPUT_DIR/traffic_live_$(date +%Y%m%d_%H%M%S).pcap"
    
    # Capture with live display and save to file
    if [[ -n "$FILTER" ]]; then
        timeout "$DURATION" tshark -i "$INTERFACE" -f "$FILTER" -w "$PCAP_FILE" \
            -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null
    else
        timeout "$DURATION" tshark -i "$INTERFACE" -w "$PCAP_FILE" \
            -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null
    fi
    
    echo ""
    echo -e "${GREEN}[+] Capture saved: $PCAP_FILE${NC}"
}

# Sub-function: DNS Extraction
capture_dns_extraction() {
    if ! command -v tshark &>/dev/null; then
        echo -e "${RED}[!] tshark required for DNS extraction. Install: apt install tshark${NC}"
        return
    fi
    
    echo -e "${BLUE}[*] Capturing traffic and extracting DNS queries...${NC}"
    echo -e "${YELLOW}[i] This reveals which domains the IoT device contacts${NC}"
    echo ""
    
    PCAP_FILE="$OUTPUT_DIR/traffic_dns_$(date +%Y%m%d_%H%M%S).pcap"
    DNS_FILE="$OUTPUT_DIR/dns_queries.txt"
    
    # Capture traffic
    if [[ -n "$FILTER" ]]; then
        timeout "$DURATION" tcpdump -i "$INTERFACE" $FILTER -s 0 -w "$PCAP_FILE" 2>/dev/null &
    else
        timeout "$DURATION" tcpdump -i "$INTERFACE" -s 0 -w "$PCAP_FILE" 2>/dev/null &
    fi
    
    echo -e "${GREEN}[+] Capturing for $DURATION seconds...${NC}"
    sleep "$DURATION"
    
    echo -e "${BLUE}[*] Extracting DNS information...${NC}"
    
    # Extract DNS queries
    echo "DNS Queries Extracted - $(date)" > "$DNS_FILE"
    echo "Source: $PCAP_FILE" >> "$DNS_FILE"
    echo "========================================" >> "$DNS_FILE"
    echo "" >> "$DNS_FILE"
    
    echo "=== DNS Queries ===" >> "$DNS_FILE"
    tshark -r "$PCAP_FILE" -Y "dns.flags.response == 0" \
        -T fields -e frame.time -e ip.src -e dns.qry.name 2>/dev/null | sort -u >> "$DNS_FILE"
    
    echo "" >> "$DNS_FILE"
    echo "=== Unique Domains Contacted ===" >> "$DNS_FILE"
    tshark -r "$PCAP_FILE" -Y "dns" -T fields -e dns.qry.name 2>/dev/null | sort -u >> "$DNS_FILE"
    
    echo "" >> "$DNS_FILE"
    echo "=== DNS Responses (IPs resolved) ===" >> "$DNS_FILE"
    tshark -r "$PCAP_FILE" -Y "dns.flags.response == 1" \
        -T fields -e dns.qry.name -e dns.a 2>/dev/null | sort -u >> "$DNS_FILE"
    
    echo ""
    echo -e "${GREEN}[+] DNS extraction complete!${NC}"
    echo -e "${GREEN}[+] Results saved to: $DNS_FILE${NC}"
    echo ""
    echo -e "${BLUE}[i] Quick preview of domains contacted:${NC}"
    tshark -r "$PCAP_FILE" -Y "dns" -T fields -e dns.qry.name 2>/dev/null | sort -u | head -20
}

# Sub-function: HTTP Analysis
capture_http_analysis() {
    if ! command -v tshark &>/dev/null; then
        echo -e "${RED}[!] tshark required for HTTP analysis. Install: apt install tshark${NC}"
        return
    fi
    
    echo -e "${BLUE}[*] Capturing traffic and extracting HTTP information...${NC}"
    echo -e "${YELLOW}[i] This finds unencrypted HTTP API calls and data${NC}"
    echo ""
    
    PCAP_FILE="$OUTPUT_DIR/traffic_http_$(date +%Y%m%d_%H%M%S).pcap"
    HTTP_FILE="$OUTPUT_DIR/http_analysis.txt"
    
    # Capture traffic
    if [[ -n "$FILTER" ]]; then
        timeout "$DURATION" tcpdump -i "$INTERFACE" $FILTER -s 0 -w "$PCAP_FILE" 2>/dev/null &
    else
        timeout "$DURATION" tcpdump -i "$INTERFACE" -s 0 -w "$PCAP_FILE" 2>/dev/null &
    fi
    
    echo -e "${GREEN}[+] Capturing for $DURATION seconds...${NC}"
    sleep "$DURATION"
    
    echo -e "${BLUE}[*] Extracting HTTP information...${NC}"
    
    echo "HTTP Analysis Report - $(date)" > "$HTTP_FILE"
    echo "Source: $PCAP_FILE" >> "$HTTP_FILE"
    echo "========================================" >> "$HTTP_FILE"
    echo "" >> "$HTTP_FILE"
    
    echo "=== HTTP Requests ===" >> "$HTTP_FILE"
    tshark -r "$PCAP_FILE" -Y "http.request" \
        -T fields -e ip.src -e http.request.method -e http.host -e http.request.uri 2>/dev/null >> "$HTTP_FILE"
    
    echo "" >> "$HTTP_FILE"
    echo "=== HTTP User-Agents (Device/App Identification) ===" >> "$HTTP_FILE"
    tshark -r "$PCAP_FILE" -Y "http.user_agent" \
        -T fields -e http.user_agent 2>/dev/null | sort -u >> "$HTTP_FILE"
    
    echo "" >> "$HTTP_FILE"
    echo "=== HTTP Hosts Contacted ===" >> "$HTTP_FILE"
    tshark -r "$PCAP_FILE" -Y "http.host" \
        -T fields -e http.host 2>/dev/null | sort -u >> "$HTTP_FILE"
    
    echo "" >> "$HTTP_FILE"
    echo "=== POST Requests (potential data exfil) ===" >> "$HTTP_FILE"
    tshark -r "$PCAP_FILE" -Y "http.request.method == POST" \
        -T fields -e ip.dst -e http.host -e http.request.uri 2>/dev/null >> "$HTTP_FILE"
    
    echo ""
    echo -e "${GREEN}[+] HTTP analysis complete!${NC}"
    echo -e "${GREEN}[+] Results saved to: $HTTP_FILE${NC}"
    
    # Check for any HTTP traffic
    HTTP_COUNT=$(tshark -r "$PCAP_FILE" -Y "http" 2>/dev/null | wc -l)
    if [[ $HTTP_COUNT -eq 0 ]]; then
        echo -e "${YELLOW}[i] No HTTP traffic detected. Device may use HTTPS only.${NC}"
    else
        echo ""
        echo -e "${BLUE}[i] Quick preview:${NC}"
        tshark -r "$PCAP_FILE" -Y "http.request" \
            -T fields -e http.request.method -e http.host -e http.request.uri 2>/dev/null | head -10
    fi
}

# Sub-function: Protocol Statistics
capture_protocol_stats() {
    if ! command -v tshark &>/dev/null; then
        echo -e "${RED}[!] tshark required for protocol stats. Install: apt install tshark${NC}"
        return
    fi
    
    echo -e "${BLUE}[*] Capturing traffic and analyzing protocol distribution...${NC}"
    echo ""
    
    PCAP_FILE="$OUTPUT_DIR/traffic_stats_$(date +%Y%m%d_%H%M%S).pcap"
    STATS_FILE="$OUTPUT_DIR/protocol_stats.txt"
    
    # Capture traffic
    if [[ -n "$FILTER" ]]; then
        timeout "$DURATION" tcpdump -i "$INTERFACE" $FILTER -s 0 -w "$PCAP_FILE" 2>/dev/null &
    else
        timeout "$DURATION" tcpdump -i "$INTERFACE" -s 0 -w "$PCAP_FILE" 2>/dev/null &
    fi
    
    echo -e "${GREEN}[+] Capturing for $DURATION seconds...${NC}"
    sleep "$DURATION"
    
    echo -e "${BLUE}[*] Generating protocol statistics...${NC}"
    
    echo "Protocol Statistics Report - $(date)" > "$STATS_FILE"
    echo "Source: $PCAP_FILE" >> "$STATS_FILE"
    echo "========================================" >> "$STATS_FILE"
    echo "" >> "$STATS_FILE"
    
    echo "=== Protocol Hierarchy ===" >> "$STATS_FILE"
    tshark -r "$PCAP_FILE" -q -z io,phs 2>/dev/null >> "$STATS_FILE"
    
    echo "" >> "$STATS_FILE"
    echo "=== Endpoint Statistics (IP addresses) ===" >> "$STATS_FILE"
    tshark -r "$PCAP_FILE" -q -z endpoints,ip 2>/dev/null >> "$STATS_FILE"
    
    echo "" >> "$STATS_FILE"
    echo "=== Conversations ===" >> "$STATS_FILE"
    tshark -r "$PCAP_FILE" -q -z conv,ip 2>/dev/null >> "$STATS_FILE"
    
    echo "" >> "$STATS_FILE"
    echo "=== Top Talkers (by bytes) ===" >> "$STATS_FILE"
    tshark -r "$PCAP_FILE" -q -z endpoints,ip 2>/dev/null | head -20 >> "$STATS_FILE"
    
    echo ""
    echo -e "${GREEN}[+] Protocol statistics complete!${NC}"
    echo -e "${GREEN}[+] Results saved to: $STATS_FILE${NC}"
    echo ""
    echo -e "${BLUE}[i] Protocol Hierarchy:${NC}"
    tshark -r "$PCAP_FILE" -q -z io,phs 2>/dev/null | head -30
}

# Sub-function: Full Analysis (Combined)
capture_full_analysis() {
    if ! command -v tshark &>/dev/null; then
        echo -e "${RED}[!] tshark required for full analysis. Install: apt install tshark${NC}"
        echo -e "${YELLOW}[i] Falling back to basic capture...${NC}"
        capture_basic
        return
    fi
    
    echo -e "${BLUE}[*] Starting comprehensive traffic analysis...${NC}"
    echo ""
    
    PCAP_FILE="$OUTPUT_DIR/traffic_full_$(date +%Y%m%d_%H%M%S).pcap"
    FULL_REPORT="$OUTPUT_DIR/traffic_report.txt"
    
    # Capture traffic
    if [[ -n "$FILTER" ]]; then
        tcpdump -i "$INTERFACE" $FILTER -s 0 -w "$PCAP_FILE" 2>/dev/null &
    else
        tcpdump -i "$INTERFACE" -s 0 -w "$PCAP_FILE" 2>/dev/null &
    fi
    PID=$!
    
    echo -e "${GREEN}[+] Capturing for $DURATION seconds...${NC}"
    sleep "$DURATION"
    kill $PID 2>/dev/null
    
    echo ""
    echo -e "${BLUE}[*] Analyzing captured traffic...${NC}"
    
    # Generate comprehensive report
    echo "========================================" > "$FULL_REPORT"
    echo "   IoT TRAFFIC ANALYSIS REPORT" >> "$FULL_REPORT"
    echo "========================================" >> "$FULL_REPORT"
    echo "Generated: $(date)" >> "$FULL_REPORT"
    echo "Target: ${TARGET_IP:-All traffic}" >> "$FULL_REPORT"
    echo "Duration: ${DURATION}s" >> "$FULL_REPORT"
    echo "Capture File: $PCAP_FILE" >> "$FULL_REPORT"
    echo "" >> "$FULL_REPORT"
    
    # Packet count
    PACKET_COUNT=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
    echo "Total Packets: $PACKET_COUNT" >> "$FULL_REPORT"
    echo "" >> "$FULL_REPORT"
    
    # Protocol hierarchy
    echo "========================================" >> "$FULL_REPORT"
    echo "PROTOCOL HIERARCHY" >> "$FULL_REPORT"
    echo "========================================" >> "$FULL_REPORT"
    tshark -r "$PCAP_FILE" -q -z io,phs 2>/dev/null >> "$FULL_REPORT"
    echo "" >> "$FULL_REPORT"
    
    # DNS domains
    echo "========================================" >> "$FULL_REPORT"
    echo "DOMAINS CONTACTED (DNS)" >> "$FULL_REPORT"
    echo "========================================" >> "$FULL_REPORT"
    tshark -r "$PCAP_FILE" -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null | sort -u >> "$FULL_REPORT"
    echo "" >> "$FULL_REPORT"
    
    # External IPs
    echo "========================================" >> "$FULL_REPORT"
    echo "EXTERNAL IPs CONTACTED" >> "$FULL_REPORT"
    echo "========================================" >> "$FULL_REPORT"
    tshark -r "$PCAP_FILE" -T fields -e ip.dst 2>/dev/null | sort -u | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" >> "$FULL_REPORT"
    echo "" >> "$FULL_REPORT"
    
    # HTTP hosts
    echo "========================================" >> "$FULL_REPORT"
    echo "HTTP HOSTS (unencrypted)" >> "$FULL_REPORT"
    echo "========================================" >> "$FULL_REPORT"
    tshark -r "$PCAP_FILE" -Y "http.host" -T fields -e http.host 2>/dev/null | sort -u >> "$FULL_REPORT"
    echo "" >> "$FULL_REPORT"
    
    # TLS SNI (encrypted destinations)
    echo "========================================" >> "$FULL_REPORT"
    echo "TLS/HTTPS DESTINATIONS (SNI)" >> "$FULL_REPORT"
    echo "========================================" >> "$FULL_REPORT"
    tshark -r "$PCAP_FILE" -Y "tls.handshake.extensions_server_name" \
        -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u >> "$FULL_REPORT"
    echo "" >> "$FULL_REPORT"
    
    # Conversations summary
    echo "========================================" >> "$FULL_REPORT"
    echo "IP CONVERSATIONS" >> "$FULL_REPORT"
    echo "========================================" >> "$FULL_REPORT"
    tshark -r "$PCAP_FILE" -q -z conv,ip 2>/dev/null >> "$FULL_REPORT"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}[+] Full analysis complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}Files created:${NC}"
    echo "  - Capture:  $PCAP_FILE"
    echo "  - Report:   $FULL_REPORT"
    echo ""
    echo -e "${BLUE}[i] Quick Summary:${NC}"
    echo "  Packets captured: $PACKET_COUNT"
    echo ""
    echo "  Domains contacted:"
    tshark -r "$PCAP_FILE" -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null | sort -u | head -10
    echo ""
    echo "  TLS/HTTPS destinations:"
    tshark -r "$PCAP_FILE" -Y "tls.handshake.extensions_server_name" \
        -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u | head -10
}

# --- MODE 4: SSL/TLS ANALYSIS ---
ssl_probe() {
    # Check if target IP is set
    if [[ -z "$TARGET_IP" ]]; then
        echo -e "${RED}[!] No target IP set. Please enter an IP address:${NC}"
        read -p "IoT Device IP: " TARGET_IP
    fi
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}       SSL/TLS ANALYSIS OPTIONS         ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${GREEN}Target: $TARGET_IP${NC}"
    echo ""
    echo "Select an analysis mode:"
    echo ""
    echo "  1) Certificate Probe   - Extract SSL certificates from common ports"
    echo ""
    echo "  2) Cipher Analysis     - Enumerate supported cipher suites (security check)"
    echo ""
    echo "  3) TLS Fingerprint     - Capture TLS parameters for library identification"
    echo "                          (JA3-style: cipher suites, extensions, curves)"
    echo ""
    echo "  4) RSA Key Analysis    - Check for weak RSA keys using RsaCtfTool"
    echo "                          (Detects ROCA, small primes, weak keys)"
    echo ""
    echo "  5) Full Analysis       - Run all of the above"
    echo ""
    echo "  6) Back to main menu"
    echo ""
    read -p "Choice [1-6]: " ssl_choice
    
    # Common IoT SSL ports
    PORTS=("443" "8443" "8008" "8080" "8883" "1883")
    
    case $ssl_choice in
        1)
            ssl_cert_probe
            ;;
        2)
            ssl_cipher_analysis
            ;;
        3)
            ssl_tls_fingerprint
            ;;
        4)
            ssl_rsa_analysis
            ;;
        5)
            echo -e "${BLUE}[*] Running full SSL/TLS analysis...${NC}"
            ssl_cert_probe
            ssl_cipher_analysis
            ssl_tls_fingerprint
            ssl_rsa_analysis
            ;;
        6)
            return
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            return
            ;;
    esac
    echo "-------------------------------------"
}

# Sub-function: Certificate Probe
ssl_cert_probe() {
    echo ""
    echo -e "${BLUE}[*] Probing SSL/TLS Certificates...${NC}"
    
    for port in "${PORTS[@]}"; do
        echo -e "${YELLOW}[*] Testing Port $port...${NC}"
        timeout 5 bash -c "echo 'Q' | openssl s_client -connect '$TARGET_IP:$port' -showcerts 2>&1" > "$OUTPUT_DIR/ssl_cert_$port.txt"
        
        if grep -q "BEGIN CERTIFICATE" "$OUTPUT_DIR/ssl_cert_$port.txt"; then
            echo -e "${GREEN}[+] Certificate found on port $port!${NC}"
            echo -e "    Subject: $(grep 'subject=' "$OUTPUT_DIR/ssl_cert_$port.txt" | head -1)"
            echo -e "    Issuer:  $(grep 'issuer=' "$OUTPUT_DIR/ssl_cert_$port.txt" | head -1)"
            
            # Check for self-signed cert (common IoT issue from the paper)
            if grep -q "self-signed" "$OUTPUT_DIR/ssl_cert_$port.txt" 2>/dev/null || \
               grep -q "verify error:num=18" "$OUTPUT_DIR/ssl_cert_$port.txt" 2>/dev/null; then
                echo -e "    ${YELLOW}[!] WARNING: Self-signed certificate detected${NC}"
            fi
            
            # Extract certificate for further analysis
            openssl s_client -connect "$TARGET_IP:$port" </dev/null 2>/dev/null | \
                openssl x509 -outform PEM > "$OUTPUT_DIR/cert_$port.pem" 2>/dev/null
        else
            rm -f "$OUTPUT_DIR/ssl_cert_$port.txt"
        fi
    done
}

# Sub-function: Cipher Suite Analysis
ssl_cipher_analysis() {
    echo ""
    echo -e "${BLUE}[*] Analyzing Cipher Suites...${NC}"
    echo -e "${YELLOW}[i] This helps identify SSL library and security posture${NC}"
    
    for port in "${PORTS[@]}"; do
        # Quick check if port is open with SSL
        if timeout 3 bash -c "echo '' | openssl s_client -connect '$TARGET_IP:$port' 2>&1" | grep -q "BEGIN CERTIFICATE"; then
            echo -e "${GREEN}[+] Port $port - Enumerating ciphers...${NC}"
            
            # Use nmap ssl-enum-ciphers for detailed analysis
            nmap -Pn -p "$port" --script ssl-enum-ciphers "$TARGET_IP" -oN "$OUTPUT_DIR/ssl_ciphers_$port.txt" 2>/dev/null
            
            # Check for weak ciphers
            if grep -qiE "(RC4|DES|NULL|EXPORT|MD5|anon)" "$OUTPUT_DIR/ssl_ciphers_$port.txt" 2>/dev/null; then
                echo -e "    ${RED}[!] WEAK CIPHERS DETECTED on port $port${NC}"
            fi
            
            # Check TLS version
            if grep -qi "TLSv1.0\|TLSv1.1\|SSLv3" "$OUTPUT_DIR/ssl_ciphers_$port.txt" 2>/dev/null; then
                echo -e "    ${YELLOW}[!] Outdated TLS version detected on port $port${NC}"
            fi
        fi
    done
}

# Sub-function: TLS Fingerprinting (JA3-style)
ssl_tls_fingerprint() {
    echo ""
    echo -e "${BLUE}[*] Capturing TLS Fingerprint Data...${NC}"
    echo -e "${YELLOW}[i] Extracting parameters for SSL library identification${NC}"
    echo ""
    
    FINGERPRINT_FILE="$OUTPUT_DIR/tls_fingerprint.txt"
    echo "TLS Fingerprint Report - $(date)" > "$FINGERPRINT_FILE"
    echo "Target: $TARGET_IP" >> "$FINGERPRINT_FILE"
    echo "========================================" >> "$FINGERPRINT_FILE"
    
    for port in "${PORTS[@]}"; do
        # Get detailed SSL info with -msg flag to see handshake
        OUTPUT=$(timeout 5 bash -c "echo '' | openssl s_client -connect '$TARGET_IP:$port' -servername '$TARGET_IP' -msg 2>&1")
        
        if echo "$OUTPUT" | grep -q "BEGIN CERTIFICATE"; then
            echo -e "${GREEN}[+] Port $port - Extracting TLS parameters...${NC}"
            echo "" >> "$FINGERPRINT_FILE"
            echo "Port: $port" >> "$FINGERPRINT_FILE"
            echo "----------------------------------------" >> "$FINGERPRINT_FILE"
            
            # Extract TLS version
            TLS_VER=$(echo "$OUTPUT" | grep -o 'Protocol.*:.*' | head -1)
            echo "TLS Version: $TLS_VER" >> "$FINGERPRINT_FILE"
            echo "  TLS Version: $TLS_VER"
            
            # Extract cipher used
            CIPHER=$(echo "$OUTPUT" | grep -o 'Cipher.*:.*' | head -1)
            echo "Cipher: $CIPHER" >> "$FINGERPRINT_FILE"
            echo "  Cipher: $CIPHER"
            
            # Extract certificate info for library hints
            CERT_SIG=$(echo "$OUTPUT" | grep -o 'Signature Algorithm:.*' | head -1)
            echo "Signature: $CERT_SIG" >> "$FINGERPRINT_FILE"
            
            # Look for library-specific indicators
            echo "" >> "$FINGERPRINT_FILE"
            echo "Library Indicators:" >> "$FINGERPRINT_FILE"
            
            # Common IoT TLS libraries based on paper findings
            if echo "$OUTPUT" | grep -qi "mbedTLS\|mbed TLS"; then
                echo "  Detected: mbedTLS (common in embedded IoT)" >> "$FINGERPRINT_FILE"
                echo -e "    ${BLUE}[i] Library hint: mbedTLS${NC}"
            elif echo "$OUTPUT" | grep -qi "wolfSSL\|CyaSSL"; then
                echo "  Detected: wolfSSL (embedded devices)" >> "$FINGERPRINT_FILE"
                echo -e "    ${BLUE}[i] Library hint: wolfSSL${NC}"
            elif echo "$OUTPUT" | grep -qi "OpenSSL"; then
                echo "  Detected: OpenSSL" >> "$FINGERPRINT_FILE"
                echo -e "    ${BLUE}[i] Library hint: OpenSSL${NC}"
            elif echo "$OUTPUT" | grep -qi "BoringSSL"; then
                echo "  Detected: BoringSSL (Google)" >> "$FINGERPRINT_FILE"
                echo -e "    ${BLUE}[i] Library hint: BoringSSL${NC}"
            fi
        fi
    done
    
    echo ""
    echo -e "${GREEN}[+] TLS fingerprint data saved to $FINGERPRINT_FILE${NC}"
}

# Sub-function: RSA Key Weakness Analysis
ssl_rsa_analysis() {
    echo ""
    echo -e "${BLUE}[*] RSA Key Analysis...${NC}"
    
    # Check if RsaCtfTool is available
    if command -v RsaCtfTool &>/dev/null || command -v python3 &>/dev/null && [[ -d "/opt/RsaCtfTool" || -d "$HOME/RsaCtfTool" ]]; then
        RSATOOL=""
        if command -v RsaCtfTool &>/dev/null; then
            RSATOOL="RsaCtfTool"
        elif [[ -d "/opt/RsaCtfTool" ]]; then
            RSATOOL="python3 /opt/RsaCtfTool/RsaCtfTool.py"
        elif [[ -d "$HOME/RsaCtfTool" ]]; then
            RSATOOL="python3 $HOME/RsaCtfTool/RsaCtfTool.py"
        fi
        
        if [[ -n "$RSATOOL" ]]; then
            echo -e "${GREEN}[+] RsaCtfTool found. Analyzing extracted certificates...${NC}"
            
            for cert in "$OUTPUT_DIR"/cert_*.pem; do
                if [[ -f "$cert" ]]; then
                    echo -e "${YELLOW}[*] Analyzing: $cert${NC}"
                    
                    # Extract public key
                    openssl x509 -in "$cert" -pubkey -noout > "${cert%.pem}_pubkey.pem" 2>/dev/null
                    
                    # Check for ROCA vulnerability
                    echo -e "    Checking for ROCA vulnerability..."
                    $RSATOOL --isroca --publickey "${cert%.pem}_pubkey.pem" 2>/dev/null | tee -a "$OUTPUT_DIR/rsa_analysis.txt"
                    
                    # Dump key parameters
                    echo -e "    Extracting key parameters..."
                    $RSATOOL --dumpkey --key "${cert%.pem}_pubkey.pem" 2>/dev/null >> "$OUTPUT_DIR/rsa_analysis.txt"
                fi
            done
            
            echo -e "${GREEN}[+] RSA analysis saved to $OUTPUT_DIR/rsa_analysis.txt${NC}"
        fi
    else
        echo -e "${YELLOW}[i] RsaCtfTool not found. Install for advanced RSA key analysis:${NC}"
        echo "    git clone https://github.com/RsaCtfTool/RsaCtfTool.git"
        echo "    cd RsaCtfTool && pip3 install -r requirements.txt"
        echo ""
        echo -e "${BLUE}[*] Running basic RSA key size check instead...${NC}"
        
        for cert in "$OUTPUT_DIR"/cert_*.pem; do
            if [[ -f "$cert" ]]; then
                echo -e "${YELLOW}[*] Checking: $cert${NC}"
                KEY_SIZE=$(openssl x509 -in "$cert" -noout -text 2>/dev/null | grep "Public-Key:" | grep -o '[0-9]*')
                if [[ -n "$KEY_SIZE" ]]; then
                    echo "    Key Size: $KEY_SIZE bits"
                    if [[ $KEY_SIZE -lt 2048 ]]; then
                        echo -e "    ${RED}[!] WEAK: RSA key is less than 2048 bits!${NC}"
                    fi
                fi
            fi
        done
    fi
}

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
