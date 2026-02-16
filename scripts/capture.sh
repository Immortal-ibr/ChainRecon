#!/bin/bash
# capture.sh: Traffic capture and analysis functions for ChainRecon

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

# Sub-functions: capture_basic, capture_live_tshark, capture_dns_extraction, capture_http_analysis, capture_protocol_stats, capture_full_analysis
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