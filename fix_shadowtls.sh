#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━ ShadowTLS TLS 1.3 Issue Fix ━━━${NC}"
echo ""
echo -e "${YELLOW}Current Issue:${NC} ShadowTLS is showing 'TLS 1.3 is not supported' warnings"
echo ""
echo -e "${CYAN}Select a fix option:${NC}"
echo "1) Change SNI to a TLS 1.3 compatible domain (Recommended)"
echo "2) Disable strict mode (Less secure but may work with current SNI)"
echo "3) Both - Change SNI and disable strict mode"
echo "4) Test current SNI for TLS 1.3 support"
echo "0) Exit"
echo ""
read -p "Enter your choice [0-4]: " choice

case $choice in
    1)
        echo -e "\n${CYAN}Select a TLS 1.3 compatible SNI:${NC}"
        echo "1) gateway.icloud.com (Apple - Most Stable)"
        echo "2) www.microsoft.com (Microsoft)"
        echo "3) publicassets.cdn-apple.com (Apple CDN)"
        echo "4) weather-data.apple.com (Apple Weather)"
        echo "5) coding.net (Coding Platform)"
        echo "6) www.apple.com"
        echo "7) Custom domain"
        
        read -p "Enter your choice [1-7]: " sni_choice
        
        case $sni_choice in
            1) new_sni="gateway.icloud.com" ;;
            2) new_sni="www.microsoft.com" ;;
            3) new_sni="publicassets.cdn-apple.com" ;;
            4) new_sni="weather-data.apple.com" ;;
            5) new_sni="coding.net" ;;
            6) new_sni="www.apple.com" ;;
            7) 
                read -p "Enter custom domain: " new_sni
                if [[ -z "$new_sni" ]]; then
                    echo -e "${RED}Error: Domain cannot be empty.${NC}"
                    exit 1
                fi
                ;;
            *)
                echo -e "${RED}Invalid choice.${NC}"
                exit 1
                ;;
        esac
        
        echo -e "${BLUE}Updating SNI to: $new_sni${NC}"
        sudo jq ".inbounds = [.inbounds[] | if .type == \"shadowtls\" then .handshake.server = \"$new_sni\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
        sudo mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        sudo chown sing-box:sing-box /etc/sing-box/config.json
        sudo chmod 640 /etc/sing-box/config.json
        
        echo -e "${BLUE}Restarting sing-box service...${NC}"
        sudo systemctl restart sing-box
        
        if sudo systemctl is-active --quiet sing-box; then
            echo -e "${GREEN}✓ SNI updated successfully to: $new_sni${NC}"
            echo -e "${YELLOW}Please test your connection. If issues persist, try option 2 or 3.${NC}"
        else
            echo -e "${RED}✗ Service failed to restart. Check logs: sudo journalctl -u sing-box -e${NC}"
        fi
        ;;
        
    2)
        echo -e "${BLUE}Disabling strict mode...${NC}"
        sudo jq '.inbounds = [.inbounds[] | if .type == "shadowtls" then .strict_mode = false else . end]' /etc/sing-box/config.json > /tmp/sing-box-temp.json
        sudo mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        sudo chown sing-box:sing-box /etc/sing-box/config.json
        sudo chmod 640 /etc/sing-box/config.json
        
        echo -e "${BLUE}Restarting sing-box service...${NC}"
        sudo systemctl restart sing-box
        
        if sudo systemctl is-active --quiet sing-box; then
            echo -e "${GREEN}✓ Strict mode disabled successfully${NC}"
            echo -e "${YELLOW}Note: This reduces security but should resolve the TLS 1.3 warning.${NC}"
        else
            echo -e "${RED}✗ Service failed to restart. Check logs: sudo journalctl -u sing-box -e${NC}"
        fi
        ;;
        
    3)
        echo -e "\n${CYAN}Select a TLS 1.3 compatible SNI:${NC}"
        echo "1) gateway.icloud.com (Apple - Most Stable)"
        echo "2) www.microsoft.com (Microsoft)"
        echo "3) publicassets.cdn-apple.com (Apple CDN)"
        echo "4) weather-data.apple.com (Apple Weather)"
        
        read -p "Enter your choice [1-4]: " sni_choice
        
        case $sni_choice in
            1) new_sni="gateway.icloud.com" ;;
            2) new_sni="www.microsoft.com" ;;
            3) new_sni="publicassets.cdn-apple.com" ;;
            4) new_sni="weather-data.apple.com" ;;
            *)
                new_sni="gateway.icloud.com"
                echo -e "${YELLOW}Invalid choice. Using default: gateway.icloud.com${NC}"
                ;;
        esac
        
        echo -e "${BLUE}Updating SNI to: $new_sni and disabling strict mode...${NC}"
        sudo jq ".inbounds = [.inbounds[] | if .type == \"shadowtls\" then (.handshake.server = \"$new_sni\" | .strict_mode = false) else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
        sudo mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        sudo chown sing-box:sing-box /etc/sing-box/config.json
        sudo chmod 640 /etc/sing-box/config.json
        
        echo -e "${BLUE}Restarting sing-box service...${NC}"
        sudo systemctl restart sing-box
        
        if sudo systemctl is-active --quiet sing-box; then
            echo -e "${GREEN}✓ Configuration updated successfully${NC}"
            echo -e "${GREEN}  - SNI: $new_sni${NC}"
            echo -e "${GREEN}  - Strict mode: disabled${NC}"
        else
            echo -e "${RED}✗ Service failed to restart. Check logs: sudo journalctl -u sing-box -e${NC}"
        fi
        ;;
        
    4)
        current_sni=$(sudo jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)
        echo -e "\n${BLUE}Testing TLS 1.3 support for current SNI: $current_sni${NC}"
        
        echo -e "${YELLOW}Running test...${NC}"
        result=$(echo | timeout 5 openssl s_client -tls1_3 -connect "$current_sni:443" -servername "$current_sni" 2>&1)
        
        if echo "$result" | grep -q "Protocol  : TLSv1.3"; then
            echo -e "${GREEN}✓ $current_sni supports TLS 1.3${NC}"
            echo -e "${YELLOW}The SNI supports TLS 1.3, but ShadowTLS still shows warnings.${NC}"
            echo -e "${YELLOW}Possible causes:${NC}"
            echo "  - Network/firewall blocking"
            echo "  - ISP interference"
            echo "  - Server-side TLS configuration issues"
            echo ""
            echo -e "${YELLOW}Recommendation: Try option 2 (disable strict mode) or change to a different SNI.${NC}"
        else
            echo -e "${RED}✗ $current_sni does NOT support TLS 1.3${NC}"
            echo -e "${YELLOW}Recommendation: Use option 1 to change to a TLS 1.3 compatible SNI.${NC}"
        fi
        ;;
        
    0)
        echo -e "${GREEN}Exiting...${NC}"
        exit 0
        ;;
        
    *)
        echo -e "${RED}Invalid choice.${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}To check the service status:${NC} sudo systemctl status sing-box"
echo -e "${BLUE}To view recent logs:${NC} sudo journalctl -u sing-box -n 50" 
