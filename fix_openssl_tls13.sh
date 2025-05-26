#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}━━━ OpenSSL TLS 1.3 Fix for Debian/Ubuntu ━━━${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS version${NC}"
    exit 1
fi

echo -e "${CYAN}Detected OS: $OS $VER${NC}"

# Check current OpenSSL version
current_version=$(openssl version | awk '{print $2}')
echo -e "${CYAN}Current OpenSSL version: $current_version${NC}"

# Check if OpenSSL supports TLS 1.3
if openssl s_client -help 2>&1 | grep -q "tls1_3"; then
    echo -e "${GREEN}✓ Your OpenSSL already supports TLS 1.3${NC}"
    
    # Test actual TLS 1.3 connectivity
    echo -e "\n${CYAN}Testing TLS 1.3 connectivity...${NC}"
    if echo "Q" | timeout 5 openssl s_client -tls1_3 -connect cloudflare.com:443 -servername cloudflare.com 2>&1 | grep -q "Protocol.*: TLSv1.3"; then
        echo -e "${GREEN}✓ TLS 1.3 connectivity is working${NC}"
        
        echo -e "\n${YELLOW}If you're still having issues with specific domains, it might be due to:${NC}"
        echo "  - Network/firewall restrictions"
        echo "  - Geographic location (some CDN nodes may not support TLS 1.3)"
        echo "  - ISP interference"
        echo ""
        echo -e "${CYAN}Try using these alternative SNIs that are known to work well:${NC}"
        echo "  - gateway.icloud.com"
        echo "  - www.microsoft.com"
        echo "  - www.apple.com"
    else
        echo -e "${RED}✗ TLS 1.3 is supported but connectivity test failed${NC}"
        echo -e "${YELLOW}This might be a network issue rather than OpenSSL${NC}"
    fi
else
    echo -e "${RED}✗ Your OpenSSL does NOT support TLS 1.3${NC}"
    echo -e "${YELLOW}Minimum required version: OpenSSL 1.1.1${NC}"
    
    # Offer to update OpenSSL
    echo ""
    echo -e "${CYAN}Would you like to update OpenSSL? (y/n)${NC}"
    read -p "Choice: " update_choice
    
    if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
        case "$OS" in
            ubuntu)
                if [[ "$VER" == "18.04" ]]; then
                    echo -e "${YELLOW}Ubuntu 18.04 detected. Need to add PPA for newer OpenSSL...${NC}"
                    apt update
                    apt install -y software-properties-common
                    add-apt-repository -y ppa:ondrej/apache2
                    apt update
                    apt install -y openssl
                elif [[ "$VER" == "20.04" || "$VER" == "22.04" || "$VER" == "24.04" ]]; then
                    echo -e "${GREEN}Ubuntu $VER should have OpenSSL 1.1.1+ by default${NC}"
                    apt update
                    apt install -y openssl
                else
                    echo -e "${YELLOW}Ubuntu $VER - attempting standard update${NC}"
                    apt update
                    apt install -y openssl
                fi
                ;;
            debian)
                if [[ "$VER" == "10" ]]; then
                    echo -e "${YELLOW}Debian 10 (Buster) detected${NC}"
                    apt update
                    apt install -y openssl
                elif [[ "$VER" == "11" || "$VER" == "12" ]]; then
                    echo -e "${GREEN}Debian $VER should have OpenSSL 1.1.1+ by default${NC}"
                    apt update
                    apt install -y openssl
                else
                    echo -e "${YELLOW}Debian $VER - attempting standard update${NC}"
                    apt update
                    apt install -y openssl
                fi
                ;;
            *)
                echo -e "${YELLOW}Unknown OS. Attempting standard update...${NC}"
                apt update
                apt install -y openssl
                ;;
        esac
        
        # Check new version
        new_version=$(openssl version | awk '{print $2}')
        echo -e "\n${CYAN}New OpenSSL version: $new_version${NC}"
        
        # Test again
        if openssl s_client -help 2>&1 | grep -q "tls1_3"; then
            echo -e "${GREEN}✓ OpenSSL now supports TLS 1.3!${NC}"
        else
            echo -e "${RED}✗ Still no TLS 1.3 support${NC}"
            echo -e "${YELLOW}You may need to:${NC}"
            echo "  1. Upgrade to a newer OS version"
            echo "  2. Compile OpenSSL from source"
            echo "  3. Use a different server with newer OS"
        fi
    fi
fi

# Additional network tests
echo -e "\n${CYAN}=== Network Connectivity Tests ===${NC}"

# Test basic HTTPS connectivity
echo -n "Testing basic HTTPS (TLS 1.2)... "
if echo "Q" | timeout 5 openssl s_client -connect google.com:443 -servername google.com 2>&1 | grep -q "SSL-Session"; then
    echo -e "${GREEN}✓ Working${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

# Test DNS resolution
echo -n "Testing DNS resolution... "
if nslookup google.com >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Working${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

# Test outbound 443 port
echo -n "Testing outbound port 443... "
if timeout 2 bash -c "</dev/tcp/google.com/443" 2>/dev/null; then
    echo -e "${GREEN}✓ Open${NC}"
else
    echo -e "${RED}✗ Blocked${NC}"
fi

echo -e "\n${CYAN}=== Recommendations ===${NC}"
echo "1. If TLS 1.3 tests fail but your OpenSSL supports it:"
echo "   - Check firewall rules (iptables -L)"
echo "   - Try different network/VPN"
echo "   - Contact your hosting provider"
echo ""
echo "2. For ShadowTLS, try these alternative configurations:"
echo "   - Disable strict mode"
echo "   - Use known working SNIs (gateway.icloud.com, www.microsoft.com)"
echo "   - Try different ports"
echo ""
echo "3. Test with curl (if available):"
echo "   curl -I --tlsv1.3 https://cloudflare.com" 
