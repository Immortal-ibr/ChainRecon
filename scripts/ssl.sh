#!/bin/bash
# ssl.sh: SSL/TLS analysis functions for ChainRecon

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
