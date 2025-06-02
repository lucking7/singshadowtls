#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
PINK='\033[0;35m'
NC='\033[0m' # No Color

# Global IP variables
ipv4_address=""
ipv6_address=""
has_ipv4=0
has_ipv6=0
primary_ip=""
country_code=""

# Function to check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi
}

# Function to check system compatibility (Debian/Ubuntu only)
check_system() {
    if [[ -f /etc/redhat-release ]]; then
        echo -e "${RED}Error: This script is only compatible with Debian/Ubuntu systems.${NC}"
        exit 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${RED}Error: systemctl not found. This script requires a systemd-based system.${NC}"
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}━━━ Checking and Installing Dependencies ━━━${NC}"
    local update_needed=0
    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        update_needed=1
    fi

    if [[ $update_needed -eq 1 ]]; then
        echo -e "${BLUE}Updating package lists...${NC}"
        apt update || { echo -e "${RED}Error: apt update failed. Please check your network and repositories.${NC}"; exit 1; }
    else
        echo -e "${GREEN}Package lists are up to date.${NC}"
    fi

    local packages_to_install=()
    if ! command -v curl >/dev/null 2>&1; then
        packages_to_install+=("curl")
    fi
    if ! command -v jq >/dev/null 2>&1; then
        packages_to_install+=("jq")
    fi

    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        echo -e "${BLUE}Installing missing dependencies: ${packages_to_install[*]}...${NC}"
        apt install -y "${packages_to_install[@]}" || { echo -e "${RED}Error: Failed to install dependencies (${packages_to_install[*]}).${NC}"; exit 1; }
        echo -e "${GREEN}Dependencies installed successfully.${NC}"
    else
        echo -e "${GREEN}All required dependencies (curl, jq) are already installed.${NC}"
    fi
}

# Function to get IP information
get_ip_info() {
    echo -e "\n${BLUE}━━━ Fetching IP Information ━━━${NC}"
    echo -e "${BLUE}Attempting to fetch IPv4 address from Cloudflare...${NC}"
    ipv4_address=$(curl -4sfS https://speed.cloudflare.com/meta | jq -r '.clientIp // empty' 2>/dev/null)
    echo -e "${BLUE}Attempting to fetch IPv6 address from Cloudflare...${NC}"
    ipv6_address=$(curl -6sfS https://speed.cloudflare.com/meta | jq -r '.clientIp // empty' 2>/dev/null)

    has_ipv4=0
    has_ipv6=0
    primary_ip=""
    local display_ip_info=""

    if [[ -n "$ipv4_address" && "$ipv4_address" != "null" ]]; then
        has_ipv4=1
        primary_ip="$ipv4_address"
        display_ip_info="IPv4: $ipv4_address"
        echo -e "${GREEN}Detected IPv4: $ipv4_address${NC}"
    else
        echo -e "${YELLOW}Could not detect IPv4 address from Cloudflare.${NC}"
    fi

    if [[ -n "$ipv6_address" && "$ipv6_address" != "null" ]]; then
        has_ipv6=1
        if [[ -z "$primary_ip" ]]; then # if no ipv4, use ipv6 as primary
            primary_ip="$ipv6_address"
        fi
        if [[ -n "$display_ip_info" ]]; then
            display_ip_info="$display_ip_info, IPv6: $ipv6_address"
        else
            display_ip_info="IPv6: $ipv6_address"
        fi
        echo -e "${GREEN}Detected IPv6: $ipv6_address${NC}"
    else
        echo -e "${YELLOW}Could not detect IPv6 address from Cloudflare.${NC}"
    fi

    if [[ -z "$primary_ip" ]]; then
        echo -e "${RED}Failed to get any IP address from Cloudflare Speed Test.${NC}"
        echo -e "${YELLOW}Attempting fallback to ip.sb to determine primary IP...${NC}"
        primary_ip=$(curl -s "https://api.ip.sb/ip" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0")
        if [[ -z "$primary_ip" ]]; then
            echo -e "${RED}Error: Failed to get IP address from ip.sb as well. Exiting.${NC}"
            exit 1
        fi
        echo -e "${CYAN}Fallback IP: ${NC}${primary_ip} ${YELLOW}(Note: Specific v4/v6 availability for strategy filtering could not be determined via fallback).${NC}"
        display_ip_info="IP (fallback): $primary_ip"
    else
        echo -e "${BLUE}Detected Public IPs: ${NC}${display_ip_info}"
    fi

    local geoip_info
    echo -e "${BLUE}Fetching GeoIP information for ${primary_ip}...${NC}"
    geoip_info=$(curl -s "https://api.ip.sb/geoip/$primary_ip" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0")
    if [[ -z "$geoip_info" ]]; then
        echo -e "${YELLOW}Warning: Failed to get location information. Country code will be 'N/A'.${NC}"
        country_code="N/A"
        return
    fi

    country_code=$(echo "$geoip_info" | jq -r '.country_code // "N/A"')
    local city=$(echo "$geoip_info" | jq -r '.city // "N/A"')
    local country=$(echo "$geoip_info" | jq -r '.country // "N/A"')
    local isp=$(echo "$geoip_info" | jq -r '.isp // "N/A"')

    echo -e "${BLUE}IP Information Details:${NC}"
    echo -e "  ${CYAN}Primary IP for Geo-lookup: ${NC}${primary_ip}"
    echo -e "  ${CYAN}Location: ${NC}${city}, ${country} (${country_code})"
    echo -e "  ${CYAN}ISP: ${NC}${isp}"
}

# Function to output node information
output_node_info() {
    echo -e "\n${YELLOW}━━━ Generated Node Information (Surge Format) ━━━${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then
        echo -e "${RED}Error: Configuration file /etc/sing-box/config.json not found.${NC}"
        return 1
    fi

    # Check if ShadowTLS is configured
    local shadowtls_inbound_exists
    shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)

    # Check for separated UDP port configuration
    local separated_udp_exists
    separated_udp_exists=$(jq -e '.inbounds[] | select(.type == "shadowsocks" and .network == "udp" and .listen != "127.0.0.1")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    
    # Get primary SS port and method
    local primary_ss_port
    primary_ss_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .listen_port' /etc/sing-box/config.json | head -1)
    local ss_method
    ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json | head -1)
    local ss_pwd
    ss_pwd=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .password' /etc/sing-box/config.json | head -1)

    # Ensure country_code is available
    if [[ -z "$country_code" ]]; then 
        echo -e "${YELLOW}Country code not available, attempting to fetch IP info...${NC}"
        get_ip_info 
        if [[ -z "$country_code" ]]; then
            echo -e "${RED}Failed to get country code. Node name will be generic.${NC}"
            country_code="VPS" # Fallback country code
        fi
    fi

    if [[ $shadowtls_inbound_exists -eq 0 ]]; then # ShadowTLS is configured
        local stls_port
        stls_port=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .listen_port' /etc/sing-box/config.json)
        local shadowtls_pwd
        shadowtls_pwd=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .users[0].password' /etc/sing-box/config.json)
        local sni
        sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)

        # Check if there's a separated UDP port
        if [[ $separated_udp_exists -eq 0 ]]; then
            local udp_port
            udp_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks" and .network == "udp" and .listen != "127.0.0.1") | .listen_port' /etc/sing-box/config.json)
            
            echo -e "${CYAN}${country_code} [ss2022][shadow-tls-v3][separated-ports]${NC} = ${PINK}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true, udp-port=${udp_port}${NC}"
            
            echo -e "\n${YELLOW}━━━ Optional Configurations ━━━${NC}"
            echo -e "${CYAN}${country_code} [ss2022][TCP-only]${NC} = ${PINK}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=false${NC}"
            echo -e "${CYAN}${country_code} [ss2022][UDP-only]${NC} = ${PINK}ss, ${primary_ip}, ${udp_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
            
            echo -e "\n${YELLOW}Note: Separated ports configuration - TCP via ShadowTLS obfuscation (${stls_port}), UDP direct (${udp_port})${NC}"
        else
            # Shared port configuration (experimental)
            echo -e "${CYAN}${country_code} [ss2022][shadow-tls-v3][shared-port]${NC} = ${PINK}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true${NC}"
            
            echo -e "\n${YELLOW}Note: Shared port configuration - Both TCP and UDP use port ${stls_port} (experimental feature)${NC}"
        fi
        
        # Output for direct internal Shadowsocks
        local internal_ss_port
        internal_ss_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks" and .listen == "127.0.0.1") | .listen_port' /etc/sing-box/config.json)
        if [[ -n "$internal_ss_port" && "$internal_ss_port" != "null" ]]; then
            echo -e "\n${YELLOW}━━━ Internal Shadowsocks Port (For debugging) ━━━${NC}"
            echo -e "${CYAN}${country_code} [ss2022][internal]${NC} = ${PINK}ss, ${primary_ip}, ${internal_ss_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
        fi
        
    else # Only Shadowsocks is configured (Pure SS mode)
        echo -e "${CYAN}${country_code} [ss2022][pure-ss]${NC} = ${PINK}ss, ${primary_ip}, ${primary_ss_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
        echo -e "\n${YELLOW}Note: Pure Shadowsocks configuration - Direct listening on port ${primary_ss_port}, no TLS obfuscation${NC}"
    fi
    
    echo -e "\n${YELLOW}Make sure your client supports the specified parameters. Adjust configuration if necessary.${NC}"
}

# Function to format and validate sing-box configuration
format_config() {
    local temp_file="/tmp/config.json.$$" 
    echo -e "${BLUE}Formatting configuration file with 'sing-box format'...${NC}"
    if sing-box format -c /etc/sing-box/config.json > "$temp_file"; then
        echo -e "${BLUE}Validating formatted configuration with 'sing-box check'...${NC}"
        if sing-box check -c "$temp_file"; then
            chown sing-box:sing-box "$temp_file"
            chmod 640 "$temp_file"
            mv "$temp_file" /etc/sing-box/config.json
            echo -e "${GREEN}Configuration formatted and validated successfully.${NC}"
            return 0
        else
            echo -e "${RED}Error: Configuration validation failed after formatting.${NC}"
            cat "$temp_file" 
            rm -f "$temp_file"
            return 1
        fi
    else
        echo -e "${RED}Error: Configuration formatting failed.${NC}"
        rm -f "$temp_file"
        return 1
    fi
}

# Function to detect system architecture
get_arch() {
    case "$(uname -m)" in
        x86_64 | amd64)           echo 'amd64' ;;
        x86 | i686 | i386)        echo '386' ;;
        armv8* | arm64 | aarch64) echo 'arm64' ;;
        armv7l)                   echo 'armv7' ;;
        s390x)                    echo 's390x' ;;
        *)                        echo -e "${RED}Unsupported CPU architecture: $(uname -m)${NC}" && exit 1 ;;
    esac
}

# Function to install Sing-Box
install_sing_box() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    Starting Sing-Box Installation                 ${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    get_ip_info 

    echo -e "\n${BLUE}━━━ Deployment Mode Selection ━━━${NC}"
    echo -e "${YELLOW}Please select deployment mode:${NC}"
    echo -e "  ${CYAN}1) Pure Shadowsocks (No obfuscation, best performance)${NC}"
    echo -e "  ${CYAN}2) ShadowTLS + Separated Ports (Recommended, TCP obfuscation + UDP independent)${NC}"
    echo -e "  ${CYAN}3) ShadowTLS + Shared Port (Experimental, TCP/UDP share same port)${NC}"
    
    local deployment_choice
    read -p "$(echo -e "${YELLOW}Please select deployment mode [1-3] (Default: 2): ${NC}")" deployment_choice
    
    local use_shadowtls=0  # 0=Pure SS, 1=ShadowTLS+Separated, 2=ShadowTLS+Shared
    local deployment_name=""
    
    case "$deployment_choice" in
        1) 
            use_shadowtls=0
            deployment_name="Pure Shadowsocks"
            echo -e "${GREEN}Selected: ${deployment_name}${NC}"
            ;;
        3) 
            use_shadowtls=2
            deployment_name="ShadowTLS + Shared Port"
            echo -e "${GREEN}Selected: ${deployment_name} (Experimental feature)${NC}"
            ;;
        *) 
            use_shadowtls=1
            deployment_name="ShadowTLS + Separated Ports"
            echo -e "${GREEN}Selected: ${deployment_name} (Recommended)${NC}"
            ;;
    esac

    ARCH=$(get_arch)
    echo -e "${BLUE}Detected Architecture: ${CYAN}$ARCH${NC}"

    echo -e "${BLUE}Fetching latest Sing-Box beta version from GitHub...${NC}"
    VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases | jq -r '.[] | select(.prerelease == true) | .tag_name' | head -n1 | sed 's/v//')
    if [[ -z "$VERSION" ]]; then
        echo -e "${RED}Error: Could not fetch the latest beta version tag from GitHub.${NC}"
        echo -e "${YELLOW}Please check your internet connection or GitHub API rate limits.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Latest Sing-Box beta version: ${CYAN}$VERSION${NC}"

    echo -e "${BLUE}Downloading Sing-Box beta ${VERSION} for ${ARCH}...${NC}"
    curl -Lo sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box_${VERSION}_linux_${ARCH}.deb"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Failed to download Sing-Box .deb package.${NC}"
        rm -f sing-box.deb
        exit 1
    fi

    echo -e "${BLUE}Installing Sing-Box package (sing-box.deb)...${NC}"
    dpkg -i sing-box.deb
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Failed to install Sing-Box package using dpkg.${NC}"
        echo -e "${YELLOW}You may need to resolve dependencies manually (e.g., 'sudo apt --fix-broken install').${NC}"
        rm -f sing-box.deb
        exit 1
    fi
    rm -f sing-box.deb
    echo -e "${GREEN}Sing-Box package installed successfully.${NC}"

    echo -e "\n${BLUE}━━━ Verifying/Setting up 'sing-box' User and Directories ━━━${NC}"
    if ! getent group sing-box > /dev/null 2>&1; then
        echo -e "${YELLOW}'sing-box' group not found. Attempting to create...${NC}"
        groupadd -r sing-box
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}Error: Failed to create 'sing-box' group. Service might fail.${NC}"
            echo -e "${YELLOW}Please create it manually ('sudo groupadd -r sing-box') and try again.${NC}"
        else
            echo -e "${GREEN}'sing-box' group created successfully.${NC}"
        fi
    else
        echo -e "${GREEN}'sing-box' group already exists.${NC}"
    fi

    if ! id -u sing-box > /dev/null 2>&1; then
        echo -e "${YELLOW}'sing-box' user not found. Attempting to create...${NC}"
        if getent group sing-box > /dev/null 2>&1; then
            useradd -r -g sing-box -s /usr/sbin/nologin -d /var/lib/sing-box sing-box
            if [[ $? -ne 0 ]]; then
                echo -e "${RED}Error: Failed to create 'sing-box' user. Service will likely fail.${NC}"
                echo -e "${YELLOW}Please create it manually (e.g., 'sudo useradd -r -g sing-box -s /usr/sbin/nologin -d /var/lib/sing-box sing-box').${NC}"
                exit 1 
            else
                echo -e "${GREEN}'sing-box' user created successfully.${NC}"
            fi
        else
            echo -e "${RED}Error: Cannot create 'sing-box' user because 'sing-box' group is missing or could not be created.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}'sing-box' user already exists.${NC}"
    fi

    echo -e "${BLUE}Configuring directory: /etc/sing-box${NC}"
    if [ ! -d "/etc/sing-box" ]; then
        mkdir -p /etc/sing-box
        echo -e "${YELLOW}/etc/sing-box directory created.${NC}"
    fi
    chown -R sing-box:sing-box /etc/sing-box
    chmod 750 /etc/sing-box 

    echo -e "${BLUE}Configuring directory: /var/lib/sing-box${NC}"
    if [ ! -d "/var/lib/sing-box" ]; then
        mkdir -p /var/lib/sing-box
        echo -e "${YELLOW}/var/lib/sing-box directory created.${NC}"
    fi
    chown -R sing-box:sing-box /var/lib/sing-box
    chmod 750 /var/lib/sing-box 

    echo -e "\n${BLUE}━━━ Initial Sing-Box Configuration ━━━${NC}"
    rm -f /etc/sing-box/config.json 

    echo -e "\n${BLUE}━━━ ShadowSocks Settings ━━━${NC}"
    echo -e "${YELLOW}Select Shadowsocks encryption method:${NC}"
    echo -e "  ${CYAN}1) 2022-blake3-aes-128-gcm${NC}"
    echo -e "  ${CYAN}2) 2022-blake3-aes-256-gcm (Default)${NC}"
    echo -e "  ${CYAN}3) 2022-blake3-chacha20-poly1305${NC}"
    echo -e "  ${CYAN}4) aes-128-gcm${NC}"
    echo -e "  ${CYAN}5) aes-256-gcm${NC}"
    echo -e "  ${CYAN}6) chacha20-ietf-poly1305${NC}"
    read -p "$(echo -e "${YELLOW}Enter your choice [1-6] (Default: 2): ${NC}")" ss_method_choice
    case "$ss_method_choice" in
        1) ss_method="2022-blake3-aes-128-gcm" ;;
        3) ss_method="2022-blake3-chacha20-poly1305" ;;
        4) ss_method="aes-128-gcm" ;;
        5) ss_method="aes-256-gcm" ;;
        6) ss_method="chacha20-ietf-poly1305" ;;
        *) ss_method="2022-blake3-aes-256-gcm" ;; 
    esac
    echo -e "${GREEN}Using Shadowsocks method: $ss_method${NC}"

    # Shadowsocks password settings
    echo -e "\n${YELLOW}Shadowsocks password configuration:${NC}"
    echo -e "  - Enter custom password"
    echo -e "  - Press Enter for random password"
    read -p "$(echo -e "${YELLOW}Enter Shadowsocks password (Press Enter for random): ${NC}")" ss_pwd
    
    if [[ -z "$ss_pwd" ]]; then
        case "$ss_method" in
            "2022-blake3-aes-128-gcm")
                ss_pwd=$(openssl rand -base64 16)
                ;;
            "2022-blake3-aes-256-gcm"|"2022-blake3-chacha20-poly1305")
                ss_pwd=$(openssl rand -base64 32)
                ;;
            *) 
                ss_pwd=$(openssl rand -base64 32) 
                ;;
        esac
        echo -e "${GREEN}Generated random Shadowsocks password.${NC}"
    else
        echo -e "${GREEN}Using custom Shadowsocks password.${NC}"
    fi

    local shadowtls_pwd=""
    if [[ $use_shadowtls -gt 0 ]]; then  # ShadowTLS + Separated or ShadowTLS + Shared
        echo -e "\n${YELLOW}ShadowTLS password configuration:${NC}"
        echo -e "  - Enter custom password"
        echo -e "  - Press Enter for random password"
        read -p "$(echo -e "${YELLOW}Enter ShadowTLS password (Press Enter for random): ${NC}")" shadowtls_pwd
        
        if [[ -z "$shadowtls_pwd" ]]; then
            shadowtls_pwd=$(openssl rand -base64 32)
            echo -e "${GREEN}Generated random ShadowTLS password.${NC}"
        else
            echo -e "${GREEN}Using custom ShadowTLS password.${NC}"
        fi
    fi

    echo -e "\n${BLUE}━━━ Port Configuration ━━━${NC}"
    local port="" # Main port (SS for pure mode, ShadowTLS for mixed modes)
    local port_prompt_text=""

    case $use_shadowtls in
        0) # Pure Shadowsocks
            port_prompt_text="Shadowsocks listening port"
            ;;
        1) # ShadowTLS + Separated Ports
            port_prompt_text="ShadowTLS listening port (TCP obfuscation port)"
            ;;
        2) # ShadowTLS + Shared Port
            port_prompt_text="ShadowTLS/UDP shared port"
            ;;
    esac

    echo -e "${YELLOW}Port configuration:${NC}"
    echo -e "  - Enter port number (10000-65535)"
    echo -e "  - Press Enter for random port"
    read -p "$(echo -e "${YELLOW}Set ${port_prompt_text} (Press Enter for random): ${NC}")" port
    
    if [[ -z "$port" ]]; then
        port=$(shuf -i 10000-65535 -n 1)
        echo -e "${BLUE}Generated random port: $port${NC}"
    fi
    
    # Validate port
    while true; do
        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}Error: Port must be numeric.${NC}"
        elif [[ "$port" -lt 10000 || "$port" -gt 65535 ]]; then
            echo -e "${RED}Error: Port must be between 10000-65535.${NC}"
        elif [[ -n $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED}Error: Port $port is already in use.${NC}"
        else
            break
        fi
        read -p "$(echo -e "${YELLOW}Please enter a new port (Press Enter for random): ${NC}")" port
        if [[ -z "$port" ]]; then
            port=$(shuf -i 10000-65535 -n 1)
            echo -e "${BLUE}Generated random port: $port${NC}"
        fi
    done
    
    echo -e "${GREEN}Will use port $port for ${deployment_name}.${NC}"
    
    # Internal SS port and UDP port configuration
    local ss_port_internal="" # Internal SS port for ShadowTLS modes
    local udp_port="" # Separated UDP port for mode 1
    
    if [[ $use_shadowtls -eq 1 ]]; then  # ShadowTLS + Separated Ports
        # Generate internal SS port
        ss_port_internal=$(shuf -i 10000-65535 -n 1)
        until [[ $ss_port_internal != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port_internal") ]]; do
            ss_port_internal=$(shuf -i 10000-65535 -n 1)
        done
        echo -e "${GREEN}Will use port $ss_port_internal for Shadowsocks (internal TCP).${NC}"
        
        # Generate UDP port (next to main port for convenience)
        udp_port=$((port + 1))
        until [[ -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$udp_port") ]]; do
            udp_port=$((udp_port + 1))
            if [[ $udp_port -gt 65535 ]]; then
                udp_port=$(shuf -i 10000-65535 -n 1)
            fi
        done
        echo -e "${GREEN}Will use port $udp_port for Shadowsocks (direct UDP).${NC}"
        
    elif [[ $use_shadowtls -eq 2 ]]; then  # ShadowTLS + Shared Port
        # Generate internal SS port for TCP
        ss_port_internal=$(shuf -i 10000-65535 -n 1)
        until [[ $ss_port_internal != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port_internal") ]]; do
            ss_port_internal=$(shuf -i 10000-65535 -n 1)
        done
        echo -e "${GREEN}Will use port $ss_port_internal for Shadowsocks (internal TCP).${NC}"
        echo -e "${YELLOW}Will attempt to use port $port for UDP (experimental - may conflict).${NC}"
    fi

    echo -e "\n${BLUE}━━━ ShadowTLS Handshake Settings ━━━${NC}"
    local proxysite=""
    local wildcard_sni=""
    if [[ $use_shadowtls -gt 0 ]]; then
        echo -e "${YELLOW}Select ShadowTLS SNI:${NC}"
        echo -e "  ${CYAN}1) p11.douyinpic.com (Douyin Image CDN - Default)${NC}"
        echo -e "  ${CYAN}2) mp.weixin.qq.com (WeChat)${NC}"
        echo -e "  ${CYAN}3) coding.net${NC}"
        echo -e "  ${CYAN}4) upyun.com (UpYun CDN)${NC}"
        echo -e "  ${CYAN}5) sns-video-hw.xhscdn.com (XiaoHongShu Video)${NC}"
        echo -e "  ${CYAN}6) sns-img-qc.xhscdn.com (XiaoHongShu Image)${NC}"
        echo -e "  ${CYAN}7) sns-video-qn.xhscdn.com (XiaoHongShu Video)${NC}"
        echo -e "  ${CYAN}8) p6-dy.byteimg.com (ByteDance CDN)${NC}"
        echo -e "  ${CYAN}9) p9-dy.byteimg.com (ByteDance CDN)${NC}"
        echo -e "  ${CYAN}10) feishu.cn (Feishu/Lark)${NC}"
        echo -e "  ${CYAN}11) douyin.com${NC}"
        echo -e "  ${CYAN}12) toutiao.com${NC}"
        echo -e "  ${CYAN}13) v6-dy-y.ixigua.com${NC}"
        echo -e "  ${CYAN}14) hls3-akm.douyucdn.cn (Douyu CDN)${NC}"
        echo -e "  ${CYAN}15) publicassets.cdn-apple.com (Apple CDN)${NC}"
        echo -e "  ${CYAN}16) weather-data.apple.com${NC}"
        echo -e "  ${CYAN}17) gateway.icloud.com (Most Stable)${NC}"
        echo -e "  ${CYAN}18) Custom domain${NC}"
        
        read -p "$(echo -e "${YELLOW}Enter your choice [1-18] (Default: 1): ${NC}")" sni_choice
        case "$sni_choice" in
            2) proxysite="mp.weixin.qq.com" ;;
            3) proxysite="coding.net" ;;
            4) proxysite="upyun.com" ;;
            5) proxysite="sns-video-hw.xhscdn.com" ;;
            6) proxysite="sns-img-qc.xhscdn.com" ;;
            7) proxysite="sns-video-qn.xhscdn.com" ;;
            8) proxysite="p6-dy.byteimg.com" ;;
            9) proxysite="p9-dy.byteimg.com" ;;
            10) proxysite="feishu.cn" ;;
            11) proxysite="douyin.com" ;;
            12) proxysite="toutiao.com" ;;
            13) proxysite="v6-dy-y.ixigua.com" ;;
            14) proxysite="hls3-akm.douyucdn.cn" ;;
            15) proxysite="publicassets.cdn-apple.com" ;;
            16) proxysite="weather-data.apple.com" ;;
            17) proxysite="gateway.icloud.com" ;;
            18) 
                read -p "$(echo -e "${YELLOW}Enter custom domain: ${NC}")" proxysite
                if [[ -z "$proxysite" ]]; then
                    proxysite="p11.douyinpic.com"
                fi
                ;;
            *) proxysite="p11.douyinpic.com" ;;
        esac
        echo -e "${GREEN}Using SNI: $proxysite${NC}"

        echo -e "\n${YELLOW}Select ShadowTLS wildcard SNI mode:${NC}"
        echo -e "  ${CYAN}1) off: Disable wildcard SNI (strict SNI match)${NC}"
        echo -e "  ${CYAN}2) authed: Change target to SNI:443 for authenticated connections (Recommended)${NC}"
        echo -e "  ${CYAN}3) all: Change target to SNI:443 for all connections${NC}"
        read -p "$(echo -e "${YELLOW}Choose an option [1-3] (Default: 2): ${NC}")" wildcard_sni_choice
        case "$wildcard_sni_choice" in
            1) wildcard_sni="off" ;;
            3) wildcard_sni="all" ;;
            *) wildcard_sni="authed" ;; 
        esac
        echo -e "${GREEN}Using wildcard_sni mode: $wildcard_sni${NC}"
    fi

    echo -e "\n${BLUE}━━━ DNS Strategy Configuration ━━━${NC}"
    echo -e "${YELLOW}Select default DNS strategy for IPv4/IPv6 resolution:${NC}"
    
    options=()
    option_tags=()
    default_option_idx=-1 

    if [[ $has_ipv4 -eq 1 && $has_ipv6 -eq 1 ]]; then 
        options+=("Prefer IPv4")         ; option_tags+=("prefer_ipv4")
        options+=("Prefer IPv6")         ; option_tags+=("prefer_ipv6")
        options+=("IPv4 only")           ; option_tags+=("ipv4_only")
        options+=("IPv6 only")           ; option_tags+=("ipv6_only")
        default_option_idx=0 
    elif [[ $has_ipv4 -eq 1 ]]; then 
        options+=("IPv4 only (Recommended)") ; option_tags+=("ipv4_only") ; default_option_idx=0
        options+=("Prefer IPv4 (Allows fallback if IPv6 becomes available later)") ; option_tags+=("prefer_ipv4")
    elif [[ $has_ipv6 -eq 1 ]]; then 
        options+=("IPv6 only (Recommended)") ; option_tags+=("ipv6_only") ; default_option_idx=0
        options+=("Prefer IPv6 (Allows fallback if IPv4 becomes available later)") ; option_tags+=("prefer_ipv6")
    else 
        echo -e "${YELLOW}Could not determine specific IP v4/v6 availability for filtering strategy options. Offering all strategies.${NC}"
        options+=("Prefer IPv4 (Default)") ; option_tags+=("prefer_ipv4") ; default_option_idx=0
        options+=("Prefer IPv6")         ; option_tags+=("prefer_ipv6")
        options+=("IPv4 only")           ; option_tags+=("ipv4_only")
        options+=("IPv6 only")           ; option_tags+=("ipv6_only")
    fi

    if [[ ${#options[@]} -eq 0 ]]; then 
        echo -e "${RED}Error: No DNS strategies available. Defaulting to 'prefer_ipv4'.${NC}"
        default_strategy="prefer_ipv4"
    else
        for i in "${!options[@]}"; do
            local option_text="${options[$i]}"
            if [[ $i -eq $default_option_idx && $default_option_idx -ne -1 && ${#options[@]} -gt 1 ]]; then 
                 echo -e "  ${CYAN}$((i+1))) ${option_text}${NC}"
            else
                 echo -e "  ${CYAN}$((i+1))) ${option_text}${NC}"
            fi
        done
        
        local prompt_text="${YELLOW}Enter your choice"
        if [[ $default_option_idx -ne -1 && ${#options[@]} -gt 1 ]]; then
            prompt_text+=" (Default: $((default_option_idx+1)))"
        elif [[ ${#options[@]} -eq 1 ]]; then 
             strategy_choice=1 
             echo -e "${YELLOW}Auto-selecting the only available option: ${options[0]}${NC}"
        fi
        prompt_text+=": ${NC}"

        if [[ ${#options[@]} -gt 1 ]]; then
            read -p "$(echo -e "$prompt_text")" strategy_choice
        fi

        if [[ -z "$strategy_choice" && $default_option_idx -ne -1 ]]; then
            default_strategy="${option_tags[$default_option_idx]}"
            echo -e "${YELLOW}No input, using default: ${options[$default_option_idx]}${NC}"
        elif [[ "$strategy_choice" -ge 1 && "$strategy_choice" -le ${#options[@]} ]]; then
            default_strategy="${option_tags[$((strategy_choice-1))]}"
        else 
            if [[ $has_ipv4 -eq 1 && $has_ipv6 -eq 0 ]]; then
                default_strategy="ipv4_only" 
            elif [[ $has_ipv6 -eq 1 && $has_ipv4 -eq 0 ]]; then
                default_strategy="ipv6_only" 
            elif [[ $default_option_idx -ne -1 ]]; then 
                default_strategy="${option_tags[$default_option_idx]}"
            else
                 default_strategy="prefer_ipv4" 
            fi
            echo -e "${YELLOW}Invalid choice or auto-selected. Using strategy: $default_strategy${NC}"
        fi
    fi
    echo -e "${GREEN}Using DNS strategy: $default_strategy${NC}"

    echo -e "\n${BLUE}━━━ Generating Configuration File ━━━${NC}"
    
    # Start building inbounds JSON
    local inbounds_json=""
    if [[ $use_shadowtls -gt 0 ]]; then
        inbounds_json=$(cat << INNER_EOF
        {
            "type": "shadowtls",
            "tag": "shadowtls-in",
            "listen": "::",
            "listen_port": $port,
            "version": 3,
            "users": [
                {
                    "password": "$shadowtls_pwd"
                }
            ],
            "handshake": {
                "server": "$proxysite",
                "server_port": 443
            },
            "strict_mode": true,
            "wildcard_sni": "$wildcard_sni",
            "detour": "shadowsocks-in"
        },
INNER_EOF
)
    fi

    # Add main Shadowsocks inbound
    if [[ $use_shadowtls -eq 0 ]]; then
        # Pure Shadowsocks mode - listen on public port
        inbounds_json+=$(cat << INNER_EOF
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": $port,
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
INNER_EOF
)
    else
        # ShadowTLS modes - internal Shadowsocks for TCP
        inbounds_json+=$(cat << INNER_EOF
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "127.0.0.1",
            "listen_port": $ss_port_internal,
            "network": "tcp",
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
INNER_EOF
)
        
        # Add UDP handling based on mode
        if [[ $use_shadowtls -eq 1 ]]; then
            # Separated UDP port
            inbounds_json+=",
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-udp",
            "listen": "::",
            "listen_port": $udp_port,
            "network": "udp",
            "method": "$ss_method",
            "password": "$ss_pwd"
        }"
        elif [[ $use_shadowtls -eq 2 ]]; then
            # Shared port UDP (experimental)
            inbounds_json+=",
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-udp",
            "listen": "::",
            "listen_port": $port,
            "network": "udp",
            "method": "$ss_method",
            "password": "$ss_pwd"
        }"
        fi
    fi

    cat << EOF > /etc/sing-box/config.json
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "tag": "dns_cf",
                "type": "https",
                "server": "1.1.1.1"
            },
            {
                "tag": "dns_google",
                "type": "https",
                "server": "8.8.8.8"
            },
            {
                "tag": "dns_resolver",
                "type": "local"
            }
        ],
        "strategy": "$default_strategy",
        "independent_cache": true,
        "rules": [
            {
                "rule_set": ["geosite-category-ads-all"],
                "action": "reject"
            },
            {
                "rule_set": ["geoip-cn", "geosite-cn"],
                "server": "dns_cf",
                "strategy": "prefer_ipv4"
            },
            {
                "rule_set": ["geosite-ai-chat-!cn"],
                "server": "dns_google",
                "strategy": "ipv4_only"
            },
            {
                "rule_set": ["geosite-google"],
                "server": "dns_google",
                "strategy": "ipv4_only"
            },
            {
                "rule_set": ["geosite-netflix"],
                "server": "dns_cf",
                "strategy": "ipv6_only"
            },
            {
                "rule_set": ["geosite-disney"],
                "server": "dns_cf",
                "strategy": "ipv6_only"
            },
            {
                "rule_set": ["geosite-category-media"],
                "server": "dns_cf",
                "strategy": "ipv6_only"
            },
            {
                "rule_set": ["geosite-spotify"],
                "server": "dns_cf",
                "strategy": "prefer_ipv4"
            },
            {
                "server": "dns_google",
                "strategy": "$default_strategy"
            }
        ]
    },
    "inbounds": [
        $inbounds_json
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ],
    "route": {
        "default_domain_resolver": {
            "server": "dns_resolver",
            "strategy": "$default_strategy"
        },
        "rules": [
            {
                "action": "sniff"
            },
            {
                "type": "logical",
                "mode": "or",
                "rules": [
                    {
                        "port": 53
                    },
                    {
                        "protocol": "dns"
                    }
                ],
                "action": "hijack-dns"
            },
            {
                "rule_set": ["geosite-category-ads-all"],
                "action": "reject"
            },
            {
                "rule_set": ["geosite-ai-chat-!cn"],
                "action": "direct"
            },
            {
                "rule_set": ["geosite-google"],
                "action": "direct"
            },
            {
                "rule_set": ["geosite-netflix"],
                "action": "direct"
            },
            {
                "rule_set": ["geosite-disney"],
                "action": "direct"
            },
            {
                "rule_set": ["geosite-category-media"],
                "action": "direct"
            },
            {
                "rule_set": ["geosite-spotify"],
                "action": "direct"
            },
            {
                "rule_set": ["geoip-cn", "geosite-cn"],
                "action": "route",
                "outbound": "direct"
            }
        ],
        "rule_set": [
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-category-ads-all",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads-all.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-ai-chat-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/category-ai-chat-!cn.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-google",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-disney",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/disney.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-category-media",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-media.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-spotify",
                "type": "remote",
                "format": "binary",
                "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/spotify.srs",
                "download_detour": "direct"
            }
        ],
        "auto_detect_interface": true,
        "final": "direct"
    },
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "/var/lib/sing-box/cache.db",
            "store_rdrc": true,
            "store_fakeip": true
        }
    }
}
EOF
    echo -e "${GREEN}Configuration file /etc/sing-box/config.json generated.${NC}"

    echo -e "${BLUE}Setting permissions for /etc/sing-box/config.json...${NC}"
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json 

    echo -e "\n${BLUE}━━━ Formatting and Validating Configuration ━━━${NC}"
    if ! format_config; then
        echo -e "${RED}Critical Error: Halting installation due to configuration error. Please check messages above.${NC}"
        echo -e "${YELLOW}The file /etc/sing-box/config.json may be invalid or an intermediate temp file might remain in /tmp/.${NC}"
        exit 1
    fi

    echo -e "\n${BLUE}━━━ Starting and Enabling Sing-Box Service ━━━${NC}"
    systemctl daemon-reload
    echo -e "${BLUE}Attempting to start sing-box service...${NC}"
    systemctl start sing-box
    echo -e "${BLUE}Attempting to enable sing-box service to start on boot...${NC}"
    systemctl enable sing-box

    if systemctl is-active --quiet sing-box && systemctl is-enabled --quiet sing-box; then
        echo -e "${GREEN}Sing-Box service started and enabled successfully.${NC}"
    else
        echo -e "${RED}Error: Sing-Box service failed to start or enable correctly.${NC}"
        echo -e "${YELLOW}Please check the service status with: systemctl status sing-box${NC}"
        echo -e "${YELLOW}And check logs with: journalctl -u sing-box -e ${NC}"
    fi

    output_node_info
    echo -e "\n${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                 Sing-Box Installation Complete                    ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
}

# Function to uninstall Sing-Box
uninstall_sing_box() {
    echo -e "${BLUE}━━━ Uninstalling Sing-Box ━━━${NC}"
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${BLUE}Stopping Sing-Box service...${NC}"
        systemctl stop sing-box
    fi
    
    if systemctl is-enabled --quiet sing-box; then
        echo -e "${BLUE}Disabling Sing-Box service...${NC}"
        systemctl disable sing-box
    fi
    
    if [[ -f /etc/systemd/system/sing-box.service ]]; then
        echo -e "${BLUE}Removing Sing-Box service file...${NC}"
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload
    fi
    
    if [[ -d /etc/sing-box ]]; then
        echo -e "${BLUE}Removing configuration directory...${NC}"
        rm -rf /etc/sing-box
    fi
    
    if [[ -f /usr/local/bin/sing-box ]]; then
        echo -e "${BLUE}Removing Sing-Box binary...${NC}"
        rm -f /usr/local/bin/sing-box
    fi
    
    if id "sing-box" &>/dev/null; then
        echo -e "${BLUE}Removing sing-box user...${NC}"
        userdel -r sing-box 2>/dev/null
    fi
    
    echo -e "${GREEN}Sing-Box has been successfully uninstalled.${NC}"
}

# Function to change port
change_port() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Change Port Configuration ━━━${NC}"
    
    # Detect current deployment mode
    local shadowtls_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    local separated_udp_exists=$(jq -e '.inbounds[] | select(.type == "shadowsocks" and .network == "udp" and .listen != "127.0.0.1")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    
    local mode_name=""
    local target_tag=""
    local service_name=""
    local is_shared_port_change=0

    if [[ $shadowtls_exists -ne 0 ]]; then # Pure SS mode
        mode_name="Pure Shadowsocks"
        echo -e "${CYAN}Current mode: $mode_name${NC}"
        target_tag="shadowsocks-in" # Assumes the main SS inbound has this tag or is the only one
        service_name="Shadowsocks (TCP/UDP)"
        
        local current_port=$(jq -r ".inbounds[] | select(.type == "shadowsocks") | .listen_port" /etc/sing-box/config.json | head -1)
        echo -e "${CYAN}Current $service_name listening port: $current_port${NC}"
        
        read -p "$(echo -e "${YELLOW}Please enter new $service_name port (10000-65535, Enter for random): ${NC}")" new_port
        if [[ -z "$new_port" ]]; then
            new_port=$(shuf -i 10000-65535 -n 1)
            echo -e "${BLUE}Generated random port: $new_port${NC}"
        fi

        if ! validate_and_check_port "$new_port"; then return 1; fi
        
        jq "(.inbounds[] | select(.type == "shadowsocks") | .listen_port) = $new_port" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json

    elif [[ $separated_udp_exists -eq 0 ]]; then # ShadowTLS + Separated UDP mode
        mode_name="ShadowTLS + Separated Ports"
        echo -e "${CYAN}Current mode: $mode_name${NC}"
        echo -e "${YELLOW}Which port would you like to modify?${NC}"
        echo -e "  ${CYAN}1) ShadowTLS (TCP obfuscation) port${NC}"
        echo -e "  ${CYAN}2) Shadowsocks internal TCP port (usually no need to change)${NC}"
        echo -e "  ${CYAN}3) Shadowsocks separated UDP port${NC}"
        read -p "$(echo -e "${YELLOW}Please enter option [1-3]: ${NC}")" port_choice

        local current_port=""
        case "$port_choice" in
            1) target_tag="shadowtls-in"; service_name="ShadowTLS (TCP obfuscation)";;
            2) target_tag="shadowsocks-in"; service_name="Shadowsocks internal TCP";; # This one listens on 127.0.0.1
            3) target_tag="shadowsocks-udp"; service_name="Shadowsocks separated UDP";;
            *) echo -e "${RED}Invalid option.${NC}"; return 1;;
        esac

        if [[ "$target_tag" == "shadowsocks-in" ]]; then
             current_port=$(jq -r ".inbounds[] | select(.tag == "$target_tag" and .listen == "127.0.0.1") | .listen_port" /etc/sing-box/config.json)
        else
             current_port=$(jq -r ".inbounds[] | select(.tag == "$target_tag") | .listen_port" /etc/sing-box/config.json)
        fi
        echo -e "${CYAN}Current $service_name port: $current_port${NC}"
        read -p "$(echo -e "${YELLOW}Please enter new $service_name port (10000-65535, Enter for random): ${NC}")" new_port
        if [[ -z "$new_port" ]]; then
            new_port=$(shuf -i 10000-65535 -n 1)
            echo -e "${BLUE}Generated random port: $new_port${NC}"
        fi

        if ! validate_and_check_port "$new_port"; then return 1; fi
        
        if [[ "$target_tag" == "shadowsocks-in" ]]; then
            jq "(.inbounds[] | select(.tag == "$target_tag" and .listen == "127.0.0.1") | .listen_port) = $new_port" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        else
            jq "(.inbounds[] | select(.tag == "$target_tag") | .listen_port) = $new_port" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        fi

    else # ShadowTLS + Shared Port mode
        mode_name="ShadowTLS + Shared Port"
        echo -e "${CYAN}Current mode: $mode_name${NC}"
        echo -e "${YELLOW}Which port would you like to modify?${NC}"
        echo -e "  ${CYAN}1) ShadowTLS and Shadowsocks UDP shared port${NC}"
        echo -e "  ${CYAN}2) Shadowsocks internal TCP port (usually no need to change)${NC}"
        read -p "$(echo -e "${YELLOW}Please enter option [1-2]: ${NC}")" port_choice
        
        local current_port=""
        case "$port_choice" in
            1) 
                target_tag="shadowtls-in" # Primary tag for shared port
                service_name="ShadowTLS/UDP shared"
                is_shared_port_change=1
                current_port=$(jq -r ".inbounds[] | select(.tag == "shadowtls-in") | .listen_port" /etc/sing-box/config.json)
                ;;
            2) 
                target_tag="shadowsocks-in" 
                service_name="Shadowsocks internal TCP"
                current_port=$(jq -r ".inbounds[] | select(.tag == "$target_tag" and .listen == "127.0.0.1") | .listen_port" /etc/sing-box/config.json)
                ;;
            *) echo -e "${RED}Invalid option.${NC}"; return 1;;
        esac
        
        echo -e "${CYAN}Current $service_name port: $current_port${NC}"
        read -p "$(echo -e "${YELLOW}Please enter new $service_name port (10000-65535, Enter for random): ${NC}")" new_port
        if [[ -z "$new_port" ]]; then
            new_port=$(shuf -i 10000-65535 -n 1)
            echo -e "${BLUE}Generated random port: $new_port${NC}"
        fi

        if ! validate_and_check_port "$new_port"; then return 1; fi

        if [[ $is_shared_port_change -eq 1 ]]; then
            # Update ShadowTLS port and the SS UDP port that shares it
            jq "(.inbounds[] | select(.tag == "shadowtls-in") | .listen_port) = $new_port | (.inbounds[] | select(.tag == "shadowsocks-udp") | .listen_port) = $new_port" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        else # Internal SS TCP port
            jq "(.inbounds[] | select(.tag == "$target_tag" and .listen == "127.0.0.1") | .listen_port) = $new_port" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        fi
    fi
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Port update failed. Check jq command and file permissions.${NC}"
        return 1
    fi
    
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        # Attempt to restore from backup if one exists from install/previous change? For now, just error out.
        return 1
    fi
    
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Port successfully changed to $new_port!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service restart failed.${NC}"
        return 1
    fi
}

# Helper function for port validation (to avoid repetition)
validate_and_check_port() {
    local port_to_validate=$1
    if [[ ! "$port_to_validate" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Error: Port must be numeric.${NC}"
        return 1
    elif [[ "$port_to_validate" -lt 10000 || "$port_to_validate" -gt 65535 ]]; then
        echo -e "${RED}Error: Port must be between 10000-65535.${NC}"
        return 1
    elif [[ -n $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port_to_validate") ]]; then
        # Allow if the port is currently used by one of our own inbounds (relevant for shared port changes)
        local current_config_ports=$(jq -r '.inbounds[].listen_port' /etc/sing-box/config.json 2>/dev/null)
        local is_own_port=0
        for p in $current_config_ports; do
            if [[ "$p" == "$port_to_validate" ]]; then
                is_own_port=1
                # If it's a shared port scenario, we might be "re-using" it for a different component.
                # This needs careful handling or a more sophisticated check.
                # For now, if it's any of our current ports, this check is tricky.
                # The port *should* be different unless we are changing an existing port to itself (no change).
                # This simple check might not be robust enough for shared port logic where the *same new port*
                # might be assigned to STLS and SS-UDP.
                # The primary check for "already in use" should ideally exclude ports currently used by sing-box itself *if*
                # we're just reconfiguring. But changing to a port used by *another* app is bad.
                
                # A simpler approach: if new_port is same as current_port, it's fine.
                # Otherwise, it must not be in use by any other process.
                # This part is tricky. The original script's port check is generally fine.
                # We should ensure we are not trying to use a port used by *another* application.
                # Ports used by sing-box itself will be freed upon restart.
            fi
        done
        if [[ $is_own_port -eq 0 ]]; then # Port is in use by something else
             echo -e "${RED}Error: Port $port_to_validate is already in use by another process.${NC}"
             return 1
        fi
        # If it's an "own port", we assume it's okay as sing-box will restart.
        # This means if the user enters the *same* port, it will pass. If they enter a port
        # used by another app, it will fail. If they enter a free port, it will pass.
    fi
    return 0
}

# Function to change Shadowsocks UDP port
change_ss_udp_port() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Change Shadowsocks UDP Port ━━━${NC}"
    
    # Get current Shadowsocks listening port
    local current_ss_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .listen_port' /etc/sing-box/config.json)
    
    if [[ -z "$current_ss_port" ]]; then
        echo -e "${RED}Error: Could not find Shadowsocks configuration.${NC}"
        return 1
    fi
    
    echo -e "${CYAN}Current Shadowsocks TCP/UDP port: $current_ss_port${NC}"
    echo -e "${YELLOW}Note: Shadowsocks uses the same port for both TCP and UDP by default.${NC}"
    echo -e "${YELLOW}Changing this port will affect both TCP and UDP traffic.${NC}"
    
    echo -e "\n${YELLOW}Port configuration:${NC}"
    echo -e "  - Enter port number (10000-65535)"
    echo -e "  - Press Enter for random port"
    read -p "$(echo -e "${YELLOW}New port: ${NC}")" new_port
    
    if [[ -z $new_port ]]; then
        # Generate random port
        new_port=$(shuf -i 10000-65535 -n 1)
        echo -e "${GREEN}Generated random port: $new_port${NC}"
    else
        # Validate port
        if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 10000 ] || [ "$new_port" -gt 65535 ]; then
            echo -e "${RED}Error: Invalid port. Must be between 10000-65535.${NC}"
            return 1
        fi
    fi
    
    # Check if port is in use
    if ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -q -w "$new_port"; then
        echo -e "${RED}Error: Port $new_port is already in use.${NC}"
        return 1
    fi
    
    # Update configuration
    jq ".inbounds = [.inbounds[] | if .type == \"shadowsocks\" then .listen_port = $new_port else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
    mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    
    # Set permissions
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    # Format and validate configuration
    if ! format_config; then
        echo -e "${RED}Error: Configuration validation failed.${NC}"
        return 1
    fi
    
    # Restart service
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Shadowsocks port changed successfully! New port: $new_port${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Function to change passwords
change_passwords() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Change Passwords ━━━${NC}"
    
    local shadowtls_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    local current_ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json | head -1)

    # Change ShadowTLS password if it exists
    if [[ $shadowtls_exists -eq 0 ]]; then
        echo -e "\n${CYAN}ShadowTLS password configuration:${NC}"
        echo -e "  - Enter custom password"
        echo -e "  - Press Enter for random password"
        read -p "$(echo -e "${YELLOW}Please enter new ShadowTLS password (Press Enter for random): ${NC}")" shadowtls_password
        
        if [[ -z "$shadowtls_password" ]]; then
            shadowtls_password=$(openssl rand -base64 32)
            echo -e "${GREEN}Generated random ShadowTLS password.${NC}"
        fi
        
        jq "(.inbounds[] | select(.type == "shadowtls") | .users[0].password) = \"$shadowtls_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        if [[ $? -ne 0 ]]; then echo -e "${RED}ShadowTLS password update failed.${NC}"; return 1; fi
        echo -e "${GREEN}ShadowTLS password updated.${NC}"
    fi
    
    # Change Shadowsocks password
    echo -e "\n${CYAN}Shadowsocks password configuration:${NC}"
    echo -e "  - Enter custom password"
    echo -e "  - Press Enter for random password"
    read -p "$(echo -e "${YELLOW}Please enter new Shadowsocks password (Press Enter for random): ${NC}")" shadowsocks_password
    
    if [[ -z "$shadowsocks_password" ]]; then
        case "$current_ss_method" in
            "2022-blake3-aes-128-gcm") shadowsocks_password=$(openssl rand -base64 16) ;; 
            "2022-blake3-aes-256-gcm"|"2022-blake3-chacha20-poly1305") shadowsocks_password=$(openssl rand -base64 32) ;; 
            *) shadowsocks_password=$(openssl rand -base64 32) ;; # Default for older methods or if method unknown
        esac
        echo -e "${GREEN}Generated random Shadowsocks password.${NC}"
    fi
    
    # Update password for all Shadowsocks inbounds
    jq "(.inbounds[] | select(.type == "shadowsocks") | .password) = \"$shadowsocks_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then echo -e "${RED}Shadowsocks password update failed.${NC}"; return 1; fi
    echo -e "${GREEN}Shadowsocks password updated (applied to all SS configurations).${NC}"
    
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Passwords successfully changed!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service restart failed.${NC}"
        return 1
    fi
}

# Function to change ShadowTLS password only
change_shadowtls_password() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    local shadowtls_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    if [[ $shadowtls_exists -ne 0 ]]; then
        echo -e "${RED}Error: ShadowTLS is not configured.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Change ShadowTLS Password ━━━${NC}"
    echo -e "  - Enter custom password"
    echo -e "  - Press Enter for random password"
    read -p "$(echo -e "${YELLOW}Please enter new ShadowTLS password (Press Enter for random): ${NC}")" new_password
    
    if [[ -z "$new_password" ]]; then
        new_password=$(openssl rand -base64 32)
        echo -e "${GREEN}Generated random password.${NC}"
    fi
    
    jq "(.inbounds[] | select(.type == "shadowtls") | .users[0].password) = \"$new_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then echo -e "${RED}ShadowTLS password update failed.${NC}"; return 1; fi
        
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}ShadowTLS password successfully changed!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service restart failed.${NC}"
        return 1
    fi
}

# Function to change ShadowTLS SNI
change_shadowtls_sni() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    # Check if ShadowTLS is configured
    local shadowtls_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    
    if [[ $shadowtls_exists -ne 0 ]]; then
        echo -e "${RED}Error: ShadowTLS is not configured.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Change ShadowTLS SNI ━━━${NC}"
    
    local current_sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)
    echo -e "${CYAN}Current SNI: $current_sni${NC}"
    
    echo -e "\n${CYAN}Select new SNI:${NC}"
    echo -e "1) p11.douyinpic.com (Douyin Image CDN)"
    echo -e "2) mp.weixin.qq.com (WeChat)"
    echo -e "3) coding.net"
    echo -e "4) upyun.com (UpYun CDN)"
    echo -e "5) sns-video-hw.xhscdn.com (XiaoHongShu Video)"
    echo -e "6) sns-img-qc.xhscdn.com (XiaoHongShu Image)"
    echo -e "7) sns-video-qn.xhscdn.com (XiaoHongShu Video)"
    echo -e "8) p6-dy.byteimg.com (ByteDance CDN)"
    echo -e "9) p9-dy.byteimg.com (ByteDance CDN)"
    echo -e "10) feishu.cn (Feishu/Lark)"
    echo -e "11) douyin.com"
    echo -e "12) toutiao.com"
    echo -e "13) v6-dy-y.ixigua.com"
    echo -e "14) hls3-akm.douyucdn.cn (Douyu CDN)"
    echo -e "15) publicassets.cdn-apple.com (Apple CDN)"
    echo -e "16) weather-data.apple.com"
    echo -e "17) gateway.icloud.com (Most Stable)"
    echo -e "18) Custom domain"
    
    read -p "Enter your choice (1-18): " sni_choice
    
    case $sni_choice in
        1) new_sni="p11.douyinpic.com" ;;
        2) new_sni="mp.weixin.qq.com" ;;
        3) new_sni="coding.net" ;;
        4) new_sni="upyun.com" ;;
        5) new_sni="sns-video-hw.xhscdn.com" ;;
        6) new_sni="sns-img-qc.xhscdn.com" ;;
        7) new_sni="sns-video-qn.xhscdn.com" ;;
        8) new_sni="p6-dy.byteimg.com" ;;
        9) new_sni="p9-dy.byteimg.com" ;;
        10) new_sni="feishu.cn" ;;
        11) new_sni="douyin.com" ;;
        12) new_sni="toutiao.com" ;;
        13) new_sni="v6-dy-y.ixigua.com" ;;
        14) new_sni="hls3-akm.douyucdn.cn" ;;
        15) new_sni="publicassets.cdn-apple.com" ;;
        16) new_sni="weather-data.apple.com" ;;
        17) new_sni="gateway.icloud.com" ;;
        18)
            read -p "Enter custom domain (e.g., www.example.com): " new_sni
            if [[ -z "$new_sni" ]]; then
                echo -e "${RED}Error: Domain cannot be empty.${NC}"
                return 1
            fi
            ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            return 1
            ;;
    esac
    
    # Update configuration
    jq ".inbounds = [.inbounds[] | if .type == \"shadowtls\" then .handshake.server = \"$new_sni\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
    mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    
    # Set permissions
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    # Format and validate configuration
    if ! format_config; then
        echo -e "${RED}Error: Configuration validation failed.${NC}"
        return 1
    fi
    
    # Restart service
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}SNI changed successfully! New SNI: $new_sni${NC}"
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Function to manage DNS strategies
manage_dns_strategies() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    # Check if config file is valid JSON
    if ! jq empty /etc/sing-box/config.json >/dev/null 2>&1; then
        echo -e "${RED}Error: Configuration file is corrupted or invalid JSON.${NC}"
        echo -e "${YELLOW}Attempting to restore from backup...${NC}"
        
        if [[ -f /etc/sing-box/config.json.bak ]]; then
            cp /etc/sing-box/config.json.bak /etc/sing-box/config.json
            echo -e "${GREEN}Configuration restored from backup.${NC}"
        else
            echo -e "${RED}No backup found. Please reinstall Sing-Box.${NC}"
            return 1
        fi
    fi
    
    # Create backup before making changes
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak.$(date +%Y%m%d_%H%M%S)
    
    echo -e "\n${BLUE}━━━ DNS Strategy Management ━━━${NC}"
    echo -e "${CYAN}Select what you want to configure:${NC}"
    echo -e "1) Change global DNS strategy"
    echo -e "2) Change streaming services strategy (Netflix, Disney, etc.)"
    echo -e "3) Change AI services strategy (ChatGPT, etc.)"
    echo -e "4) Change Google services strategy"
    echo -e "5) Change China services strategy"
    echo -e "6) View current DNS strategies"
    
    read -p "Enter your choice (1-6): " dns_choice
    
    case $dns_choice in
        1)
            echo -e "\n${CYAN}Select global DNS strategy:${NC}"
            echo -e "1) ipv4_only - Force IPv4 only"
            echo -e "2) ipv6_only - Force IPv6 only"
            echo -e "3) prefer_ipv4 - Prefer IPv4 but allow IPv6"
            echo -e "4) prefer_ipv6 - Prefer IPv6 but allow IPv4"
            
            read -p "Enter your choice (1-4): " strategy_choice
            
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;;
                2) new_strategy="ipv6_only" ;;
                3) new_strategy="prefer_ipv4" ;;
                4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
            esac
            
            # Update global DNS strategy
            jq ".dns.strategy = \"$new_strategy\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            # Also update route default_domain_resolver strategy
            jq ".route.default_domain_resolver.strategy = \"$new_strategy\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}Global DNS strategy updated to: $new_strategy${NC}"
            ;;
            
        2)
            echo -e "\n${CYAN}Select streaming services DNS strategy:${NC}"
            echo -e "1) ipv4_only - Force IPv4 (may cause issues with some services)"
            echo -e "2) ipv6_only - Force IPv6 (current default for streaming)"
            echo -e "3) prefer_ipv4 - Prefer IPv4"
            echo -e "4) prefer_ipv6 - Prefer IPv6"
            
            read -p "Enter your choice (1-4): " strategy_choice
            
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;;
                2) new_strategy="ipv6_only" ;;
                3) new_strategy="prefer_ipv4" ;;
                4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
            esac
            
            # Update Netflix, Disney, and media categories
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and (contains([\"geosite-netflix\"]) or contains([\"geosite-disney\"]) or contains([\"geosite-category-media\"]))) or (.rule_set | type == \"string\" and (. == \"geosite-netflix\" or . == \"geosite-disney\" or . == \"geosite-category-media\")) then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}Streaming services DNS strategy updated to: $new_strategy${NC}"
            ;;
            
        3)
            echo -e "\n${CYAN}Select AI services DNS strategy:${NC}"
            echo -e "1) ipv4_only - Force IPv4 (current default)"
            echo -e "2) ipv6_only - Force IPv6"
            echo -e "3) prefer_ipv4 - Prefer IPv4"
            echo -e "4) prefer_ipv6 - Prefer IPv6"
            
            read -p "Enter your choice (1-4): " strategy_choice
            
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;;
                2) new_strategy="ipv6_only" ;;
                3) new_strategy="prefer_ipv4" ;;
                4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
            esac
            
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and contains([\"geosite-ai-chat-!cn\"])) or (.rule_set | type == \"string\" and . == \"geosite-ai-chat-!cn\") then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}AI services DNS strategy updated to: $new_strategy${NC}"
            ;;
            
        4)
            echo -e "\n${CYAN}Select Google services DNS strategy:${NC}"
            echo -e "1) ipv4_only - Force IPv4 (current default)"
            echo -e "2) ipv6_only - Force IPv6"
            echo -e "3) prefer_ipv4 - Prefer IPv4"
            echo -e "4) prefer_ipv6 - Prefer IPv6"
            
            read -p "Enter your choice (1-4): " strategy_choice
            
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;;
                2) new_strategy="ipv6_only" ;;
                3) new_strategy="prefer_ipv4" ;;
                4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
            esac
            
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and contains([\"geosite-google\"])) or (.rule_set | type == \"string\" and . == \"geosite-google\") then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}Google services DNS strategy updated to: $new_strategy${NC}"
            ;;
            
        5)
            echo -e "\n${CYAN}Select China services DNS strategy:${NC}"
            echo -e "1) ipv4_only - Force IPv4"
            echo -e "2) ipv6_only - Force IPv6"
            echo -e "3) prefer_ipv4 - Prefer IPv4 (current default)"
            echo -e "4) prefer_ipv6 - Prefer IPv6"
            
            read -p "Enter your choice (1-4): " strategy_choice
            
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;;
                2) new_strategy="ipv6_only" ;;
                3) new_strategy="prefer_ipv4" ;;
                4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
            esac
            
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and (contains([\"geoip-cn\"]) or contains([\"geosite-cn\"]))) or (.rule_set | type == \"string\" and (. == \"geoip-cn\" or . == \"geosite-cn\")) then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}China services DNS strategy updated to: $new_strategy${NC}"
            ;;
            
        6)
            echo -e "\n${CYAN}Current DNS Strategies:${NC}"
            echo -e "${YELLOW}Global strategy:${NC} $(jq -r '.dns.strategy' /etc/sing-box/config.json)"
            echo -e "\n${YELLOW}Service-specific strategies:${NC}"
            
            # Show streaming services
            local streaming_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and contains(["geosite-netflix"])) or (.rule_set | type == "string" and . == "geosite-netflix")) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "Streaming (Netflix/Disney): ${streaming_strategy:-default}"
            
            # Show AI services
            local ai_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and contains(["geosite-ai-chat-!cn"])) or (.rule_set | type == "string" and . == "geosite-ai-chat-!cn")) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "AI services: ${ai_strategy:-default}"
            
            # Show Google
            local google_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and contains(["geosite-google"])) or (.rule_set | type == "string" and . == "geosite-google")) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "Google services: ${google_strategy:-default}"
            
            # Show China services
            local china_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and (contains(["geoip-cn"]) or contains(["geosite-cn"]))) or (.rule_set | type == "string" and (. == "geoip-cn" or . == "geosite-cn"))) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "China services: ${china_strategy:-default}"
            
            return 0
            ;;
            
        *)
            echo -e "${RED}Invalid choice.${NC}"
            return 1
            ;;
    esac
    
    # Set permissions
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    # Format and validate configuration
    if ! format_config; then
        echo -e "${RED}Error: Configuration validation failed.${NC}"
        return 1
    fi
    
    # Restart service
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}DNS strategy updated successfully!${NC}"
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Function to change DNS servers
change_dns_servers() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Change DNS Servers ━━━${NC}"
    echo -e "${CYAN}Current DNS servers:${NC}"
    echo -e "1) Cloudflare: 1.1.1.1"
    echo -e "2) Google: 8.8.8.8"
    
    echo -e "\n${CYAN}Select DNS server to change:${NC}"
    echo -e "1) Change primary DNS (currently Cloudflare)"
    echo -e "2) Change secondary DNS (currently Google)"
    echo -e "3) Add custom DNS server"
    
    read -p "Enter your choice (1-3): " dns_choice
    
    case $dns_choice in
        1)
            echo -e "\n${CYAN}Select new primary DNS:${NC}"
            echo -e "1) Cloudflare (1.1.1.1)"
            echo -e "2) Google (8.8.8.8)"
            echo -e "3) Quad9 (9.9.9.9)"
            echo -e "4) OpenDNS (208.67.222.222)"
            echo -e "5) Custom"
            
            read -p "Enter your choice (1-5): " server_choice
            
            case $server_choice in
                1) new_server="1.1.1.1" ;;
                2) new_server="8.8.8.8" ;;
                3) new_server="9.9.9.9" ;;
                4) new_server="208.67.222.222" ;;
                5) 
                    read -p "Enter custom DNS server IP: " new_server
                    if ! [[ "$new_server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                        echo -e "${RED}Invalid IP address.${NC}"
                        return 1
                    fi
                    ;;
                *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
            esac
            
            jq ".dns.servers[0].server = \"$new_server\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}Primary DNS server updated to: $new_server${NC}"
            ;;
            
        2)
            echo -e "\n${CYAN}Select new secondary DNS:${NC}"
            echo -e "1) Cloudflare (1.1.1.1)"
            echo -e "2) Google (8.8.8.8)"
            echo -e "3) Quad9 (9.9.9.9)"
            echo -e "4) OpenDNS (208.67.222.222)"
            echo -e "5) Custom"
            
            read -p "Enter your choice (1-5): " server_choice
            
            case $server_choice in
                1) new_server="1.1.1.1" ;;
                2) new_server="8.8.8.8" ;;
                3) new_server="9.9.9.9" ;;
                4) new_server="208.67.222.222" ;;
                5) 
                    read -p "Enter custom DNS server IP: " new_server
                    if ! [[ "$new_server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                        echo -e "${RED}Invalid IP address.${NC}"
                        return 1
                    fi
                    ;;
                *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
            esac
            
            jq ".dns.servers[1].server = \"$new_server\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}Secondary DNS server updated to: $new_server${NC}"
            ;;
            
        3)
            read -p "Enter custom DNS server IP: " new_server
            if ! [[ "$new_server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                echo -e "${RED}Invalid IP address.${NC}"
                return 1
            fi
            
            read -p "Enter a tag name for this DNS server: " dns_tag
            
            # Add new DNS server
            jq ".dns.servers += [{\"tag\": \"$dns_tag\", \"type\": \"https\", \"server\": \"$new_server\"}]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
            mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            
            echo -e "${GREEN}Custom DNS server added: $new_server (tag: $dns_tag)${NC}"
            ;;
            
        *)
            echo -e "${RED}Invalid choice.${NC}"
            return 1
            ;;
    esac
    
    # Set permissions
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    # Format and validate configuration
    if ! format_config; then
        echo -e "${RED}Error: Configuration validation failed.${NC}"
        return 1
    fi
    
    # Restart service
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}DNS servers updated successfully!${NC}"
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Function to view configuration
view_config() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Current Configuration ━━━${NC}"
    cat /etc/sing-box/config.json | jq '.'
}

# Function to view service status
check_status() {
    echo -e "\n${BLUE}━━━ Sing-Box Service Status ━━━${NC}"
    systemctl status sing-box
}

# Function to view logs
view_logs() {
    echo -e "\n${BLUE}━━━ Sing-Box Logs (Last 50 lines) ━━━${NC}"
    journalctl -u sing-box -n 50 --no-pager
}

# Function to restart service
restart_service() {
    echo -e "\n${BLUE}━━━ Restarting Sing-Box Service ━━━${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Service restarted successfully!${NC}"
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        echo -e "${YELLOW}Check logs with: journalctl -u sing-box -e${NC}"
    fi
}

# Function to change Shadowsocks method
change_ss_method() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}━━━ Change Shadowsocks Encryption Method ━━━${NC}"
    
    local current_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json | head -1)
    echo -e "${CYAN}Current encryption method: $current_method${NC}"
    
    echo -e "\n${CYAN}Please select new encryption method:${NC}"
    echo -e "  1) 2022-blake3-aes-128-gcm"
    echo -e "  2) 2022-blake3-aes-256-gcm (Recommended)"
    echo -e "  3) 2022-blake3-chacha20-poly1305"
    echo -e "  4) aes-128-gcm"
    echo -e "  5) aes-256-gcm"
    echo -e "  6) chacha20-ietf-poly1305"
    
    read -p "$(echo -e "${YELLOW}Please enter option [1-6]: ${NC}")" method_choice
    local new_method=""
    case "$method_choice" in
        1) new_method="2022-blake3-aes-128-gcm" ;; 
        2) new_method="2022-blake3-aes-256-gcm" ;; 
        3) new_method="2022-blake3-chacha20-poly1305" ;; 
        4) new_method="aes-128-gcm" ;; 
        5) new_method="aes-256-gcm" ;; 
        6) new_method="chacha20-ietf-poly1305" ;; 
        *) echo -e "${RED}Invalid option.${NC}"; return 1 ;;
    esac
    
    echo -e "\n${CYAN}Shadowsocks password configuration (new password required after encryption method change):${NC}"
    echo -e "  - Enter custom password"
    echo -e "  - Press Enter for random password"
    read -p "$(echo -e "${YELLOW}Please enter new Shadowsocks password (Press Enter for random): ${NC}")" new_password
    
    if [[ -z "$new_password" ]]; then
        case "$new_method" in
            "2022-blake3-aes-128-gcm") new_password=$(openssl rand -base64 16) ;; 
            "2022-blake3-aes-256-gcm"|"2022-blake3-chacha20-poly1305") new_password=$(openssl rand -base64 32) ;; 
            *) new_password=$(openssl rand -base64 16) ;; # Default for older methods
        esac
        echo -e "${GREEN}Generated random password for the new encryption method.${NC}"
    fi
    
    # Update method and password for all Shadowsocks inbounds
    jq "(.inbounds[] | select(.type == "shadowsocks") | .method) = \"$new_method\" | (.inbounds[] | select(.type == "shadowsocks") | .password) = \"$new_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then echo -e "${RED}Encryption method and password update failed.${NC}"; return 1; fi

    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Encryption method successfully changed to: $new_method${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service restart failed.${NC}"
        return 1
    fi
}

# Function to specifically change only Shadowsocks password
change_shadowsocks_password_only(){
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    echo -e "\n${BLUE}━━━ Change Shadowsocks Password Only ━━━${NC}"
    local current_ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json | head -1)
    echo -e "\n${CYAN}Shadowsocks password configuration:${NC}"
    echo -e "  - Enter custom password"
    echo -e "  - Press Enter for random password"
    read -p "$(echo -e "${YELLOW}Please enter new Shadowsocks password (Press Enter for random): ${NC}")" shadowsocks_password
    
    if [[ -z "$shadowsocks_password" ]]; then
        case "$current_ss_method" in
            "2022-blake3-aes-128-gcm") shadowsocks_password=$(openssl rand -base64 16) ;; 
            "2022-blake3-aes-256-gcm"|"2022-blake3-chacha20-poly1305") shadowsocks_password=$(openssl rand -base64 32) ;; 
            *) shadowsocks_password=$(openssl rand -base64 16) ;; 
        esac
        echo -e "${GREEN}Generated random Shadowsocks password.${NC}"
    fi
    
    jq "(.inbounds[] | select(.type == "shadowsocks") | .password) = \"$shadowsocks_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then echo -e "${RED}Shadowsocks password update failed.${NC}"; return 1; fi
    echo -e "${GREEN}Shadowsocks password updated (applied to all SS configurations).${NC}"

    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    if ! format_config; then echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"; return 1; fi
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Shadowsocks password successfully changed!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service restart failed.${NC}"; return 1;
    fi
}

# Function to display menu
show_menu() {
    clear
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}        ${YELLOW}Sing-Box & ShadowTLS Multi-Deployment Script v3.1${NC}        ${BLUE}│${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}▸ System Management${NC}                                           ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}1${NC}) Install/Update Sing-Box (Multiple deployment modes)     ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}2${NC}) Uninstall Sing-Box                                       ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}3${NC}) View Node Information (Generated from current config)   ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}                                                                 ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}▸ Service Control${NC}                                             ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}4${NC}) View Service Status                                      ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}5${NC}) View Service Logs                                        ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}6${NC}) Restart Service                                          ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}7${NC}) View Current Configuration (JSON format)               ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}                                                                 ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}▸ Configuration (Auto-adapts to current deployment mode)${NC}       ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}8${NC}) Port Settings (SS/STLS/UDP/Internal ports)             ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}9${NC}) Password Settings (SS/STLS)                             ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}10${NC}) ShadowTLS Settings (SNI/Password)                      ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}11${NC}) Shadowsocks Settings (Encryption/UDP port)            ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}12${NC}) DNS Settings (Strategy/Servers)                        ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}                                                                 ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}    ${CYAN}0${NC}) Exit Script                                               ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}                                                                 ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo -e ""
    echo -ne "${YELLOW}Please select an operation [0-12]: ${NC}"
}

# Function to display port submenu
show_port_menu() {
    echo -e "\n${BLUE}━━━ Port Settings (Auto-detection mode) ━━━${NC}"
    echo -e "${CYAN}1) Change Port (Smart adaptation for Pure SS/STLS Separated/STLS Shared)${NC}"
    echo -e "${CYAN}2) Change Shadowsocks UDP Port (For Pure SS or STLS Separated modes)${NC}"
    echo -e "${CYAN}0) Back to Main Menu${NC}"
    echo -ne "${YELLOW}Please select [0-2]: ${NC}"
    read -p "" port_choice
    
    case $port_choice in
        1) change_port ;; # This function is now mode-aware
        2) change_ss_udp_port ;; # This function is also mode-aware
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

# Function to display password submenu
show_password_menu() {
    echo -e "\n${BLUE}━━━ Password Settings ━━━${NC}"
    echo -e "${CYAN}1) Change All Passwords (ShadowTLS and Shadowsocks)${NC}"
    echo -e "${CYAN}2) Change ShadowTLS Password Only${NC}"
    echo -e "${CYAN}3) Change Shadowsocks Password Only (Applied to all SS configs)${NC}"
    echo -e "${CYAN}0) Back to Main Menu${NC}"
    echo -ne "${YELLOW}Please select [0-3]: ${NC}"
    read -p "" pass_choice
    
    case $pass_choice in
        1) change_passwords ;; # Handles both if STLS exists
        2) change_shadowtls_password ;; 
        3) change_shadowsocks_password_only ;; # New function needed
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

# Function to display shadowtls submenu
show_shadowtls_menu() {
    echo -e "\n${BLUE}━━━ ShadowTLS Settings (Only effective when ShadowTLS is active) ━━━${NC}"
    echo -e "${CYAN}1) Change ShadowTLS SNI Domain${NC}"
    echo -e "${CYAN}2) Change ShadowTLS Password${NC}"
    echo -e "${CYAN}0) Back to Main Menu${NC}"
    echo -ne "${YELLOW}Please select [0-2]: ${NC}"
    read -p "" stls_choice
    
    case $stls_choice in
        1) change_shadowtls_sni ;; 
        2) change_shadowtls_password ;; 
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

# Function to display shadowsocks submenu
show_shadowsocks_menu() {
    echo -e "\n${BLUE}━━━ Shadowsocks Settings ━━━${NC}"
    echo -e "${CYAN}1) Change Shadowsocks Encryption Method (Will reset password)${NC}"
    echo -e "${CYAN}2) Change Shadowsocks UDP Port (See instructions)${NC}"
    echo -e "${CYAN}3) Change Shadowsocks Password Only${NC}"
    echo -e "${CYAN}0) Back to Main Menu${NC}"
    echo -ne "${YELLOW}Please select [0-3]: ${NC}"
    read -p "" ss_choice
    
    case $ss_choice in
        1) change_ss_method ;; 
        2) change_ss_udp_port ;; 
        3) change_shadowsocks_password_only ;; # New function needed
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

# Function to display DNS submenu
show_dns_menu() {
    echo -e "\n${BLUE}━━━ DNS Settings ━━━${NC}"
    echo -e "${CYAN}1) Manage DNS Strategies${NC}"
    echo -e "${CYAN}2) Change DNS Servers${NC}"
    echo -e "${CYAN}0) Back to Main Menu${NC}"
    echo -ne "${YELLOW}Please select [0-2]: ${NC}"
    read -p "" dns_choice
    
    case $dns_choice in
        1) manage_dns_strategies ;;
        2) change_dns_servers ;;
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

# Main execution
main() {
    check_root
    check_system
    
    while true; do
        show_menu
        read -p "" choice
        
        case $choice in
            1)
                install_dependencies
                install_sing_box
                ;;
            2)
                uninstall_sing_box
                ;;
            3)
                output_node_info
                ;;
            4)
                check_status
                ;;
            5)
                view_logs
                ;;
            6)
                restart_service
                ;;
            7)
                view_config
                ;;
            8)
                show_port_menu
                ;;
            9)
                show_password_menu
                ;;
            10)
                show_shadowtls_menu
                ;;
            11)
                show_shadowsocks_menu
                ;;
            12)
                show_dns_menu
                ;;
            0)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please try again.${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read
    done
}

# Run main function
main "$@"
