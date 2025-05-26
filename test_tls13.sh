#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}Testing TLS 1.3 Support for Common SNI Domains${NC}"
echo "================================================"

# Check OpenSSL version
echo -e "${CYAN}Checking OpenSSL version...${NC}"
openssl_version=$(openssl version)
echo "OpenSSL Version: $openssl_version"

# Check if OpenSSL supports TLS 1.3
if ! openssl s_client -help 2>&1 | grep -q "tls1_3"; then
    echo -e "${RED}WARNING: Your OpenSSL version does not support TLS 1.3!${NC}"
    echo -e "${YELLOW}Please update OpenSSL to version 1.1.1 or later.${NC}"
    echo ""
    echo "To update on Debian/Ubuntu:"
    echo "  sudo apt update"
    echo "  sudo apt install openssl"
    echo ""
    exit 1
fi

# Detect timeout command variant
if command -v timeout >/dev/null 2>&1; then
    # Test if it's GNU timeout (Linux) or BSD timeout (macOS)
    if timeout --version 2>&1 | grep -q "GNU coreutils"; then
        TIMEOUT_CMD="timeout 5"
    else
        TIMEOUT_CMD="timeout 5"
    fi
else
    echo -e "${YELLOW}Warning: timeout command not found. Tests may hang.${NC}"
    TIMEOUT_CMD=""
fi

# List of domains to test
domains=(
    "mp.weixin.qq.com"
    "coding.net"
    "upyun.com"
    "sns-video-hw.xhscdn.com"
    "sns-img-qc.xhscdn.com"
    "sns-video-qn.xhscdn.com"
    "p9-dy.byteimg.com"
    "p6-dy.byteimg.com"
    "p11.douyinpic.com"
    "feishu.cn"
    "douyin.com"
    "toutiao.com"
    "v6-dy-y.ixigua.com"
    "hls3-akm.douyucdn.cn"
    "publicassets.cdn-apple.com"
    "weather-data.apple.com"
    "www.microsoft.com"
    "www.apple.com"
    "gateway.icloud.com"
)

# Function to test TLS 1.3 support
test_tls13() {
    local domain=$1
    echo -n "Testing $domain... "
    
    # Test TLS 1.3 connection with more verbose output
    if [[ -n "$TIMEOUT_CMD" ]]; then
        result=$(echo "Q" | $TIMEOUT_CMD openssl s_client -tls1_3 -connect "$domain:443" -servername "$domain" 2>&1)
    else
        result=$(echo "Q" | openssl s_client -tls1_3 -connect "$domain:443" -servername "$domain" 2>&1)
    fi
    
    # Debug: Show what we're looking for
    # echo "$result" | grep -E "(Protocol|TLSv1.3)" | head -5
    
    # Check for various indicators of TLS 1.3 support
    if echo "$result" | grep -q "Protocol  : TLSv1.3" || \
       echo "$result" | grep -q "Protocol.*: TLSv1.3" || \
       echo "$result" | grep -q "TLSv1.3" && ! echo "$result" | grep -q "tlsv1.3 alert"; then
        echo -e "${GREEN}✓ TLS 1.3 Supported${NC}"
        return 0
    else
        # Check for specific error messages
        if echo "$result" | grep -q "wrong version number"; then
            echo -e "${RED}✗ TLS 1.3 Not Supported (wrong version)${NC}"
        elif echo "$result" | grep -q "tlsv1 alert protocol version"; then
            echo -e "${RED}✗ TLS 1.3 Not Supported (protocol version alert)${NC}"
        elif echo "$result" | grep -q "Connection refused"; then
            echo -e "${RED}✗ Connection refused${NC}"
        elif echo "$result" | grep -q "No route to host"; then
            echo -e "${RED}✗ No route to host${NC}"
        elif echo "$result" | grep -q "connect:errno"; then
            echo -e "${RED}✗ Connection error${NC}"
        else
            echo -e "${RED}✗ TLS 1.3 Not Supported${NC}"
        fi
        return 1
    fi
}

# Alternative test function using nmap if available
test_tls13_nmap() {
    local domain=$1
    if command -v nmap >/dev/null 2>&1; then
        echo -e "${CYAN}Testing $domain with nmap...${NC}"
        nmap --script ssl-enum-ciphers -p 443 "$domain" | grep -A 5 "TLSv1.3"
    fi
}

# Test each domain
supported_domains=()
unsupported_domains=()
for domain in "${domains[@]}"; do
    if test_tls13 "$domain"; then
        supported_domains+=("$domain")
    else
        unsupported_domains+=("$domain")
    fi
done

echo ""
echo -e "${GREEN}=== Domains supporting TLS 1.3 (${#supported_domains[@]} domains) ===${NC}"
for domain in "${supported_domains[@]}"; do
    echo -e "  ${GREEN}✓${NC} $domain"
done

if [[ ${#unsupported_domains[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}=== Domains NOT supporting TLS 1.3 (${#unsupported_domains[@]} domains) ===${NC}"
    for domain in "${unsupported_domains[@]}"; do
        echo -e "  ${RED}✗${NC} $domain"
    done
fi

echo ""
echo -e "${YELLOW}Summary:${NC}"
echo -e "  Total tested: ${#domains[@]}"
echo -e "  ${GREEN}TLS 1.3 supported: ${#supported_domains[@]}${NC}"
echo -e "  ${RED}TLS 1.3 not supported: ${#unsupported_domains[@]}${NC}"

# Additional diagnostics
echo ""
echo -e "${CYAN}=== System Information ===${NC}"
echo "OS: $(uname -a)"
echo "OpenSSL: $(openssl version)"

# Test with a known TLS 1.3 site for verification
echo ""
echo -e "${CYAN}Testing known TLS 1.3 site (cloudflare.com) for verification...${NC}"
if echo "Q" | openssl s_client -tls1_3 -connect cloudflare.com:443 -servername cloudflare.com 2>&1 | grep -q "Protocol.*: TLSv1.3"; then
    echo -e "${GREEN}✓ Your system can connect to TLS 1.3 sites${NC}"
else
    echo -e "${RED}✗ Your system might have issues with TLS 1.3 connections${NC}"
    echo -e "${YELLOW}This could be due to:${NC}"
    echo "  - Old OpenSSL version (need 1.1.1+)"
    echo "  - Network/firewall blocking TLS 1.3"
    echo "  - ISP interference"
fi 
