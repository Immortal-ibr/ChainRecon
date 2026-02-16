#!/bin/bash
# scan.sh: Device scanning functions for ChainRecon

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