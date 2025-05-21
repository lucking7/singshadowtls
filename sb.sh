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
GRAY='\033[0;90m' # Added Gray for disabled menu items
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
    echo -e "${BLUE}--- Checking and Installing Dependencies ---${NC}"
    local update_needed=0
    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        update_needed=1
    fi

    if [[ $update_needed -eq 1 ]]; then
        echo -e "${BLUE}Updating package lists (apt update)...${NC}"
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
    echo -e "\n${BLUE}--- Fetching IP Information ---${NC}"
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
    echo -e "\n${YELLOW}--- Generated Node Information (Surge Format) ---${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then
        echo -e "${RED}Error: Configuration file /etc/sing-box/config.json not found.${NC}"
        return 1
    fi

    # Ensure country_code is available
    if [[ -z "$country_code" ]]; then 
        echo -e "${YELLOW}Country code not available, attempting to fetch IP info...${NC}"
        get_ip_info 
        if [[ -z "$country_code" ]]; then
            echo -e "${RED}Failed to get country code. Node name will be generic.${NC}"
            country_code="VPS" # Fallback country code
        fi
    fi

    local ss_method=$(jq -r '.inbounds[] | select(.tag == "shadowsocks-in") | .method' /etc/sing-box/config.json)
    local ss_pwd=$(jq -r '.inbounds[] | select(.tag == "shadowsocks-in") | .password' /etc/sing-box/config.json)
    
    has_shadowtls_inbound=$(jq -e 'any(.inbounds[]; .type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1 && echo "true" || echo "false")

    if [[ "$has_shadowtls_inbound" == "true" ]]; then
        local shadowtls_port=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .listen_port' /etc/sing-box/config.json)
        local shadowtls_pwd=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .users[0].password' /etc/sing-box/config.json)
        local sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)
        # ss_port for udp-relay will be the one shadowsocks-in listens on (which is internal if shadowtls is present)
        local ss_internal_port=$(jq -r '.inbounds[] | select(.tag == "shadowsocks-in") | .listen_port' /etc/sing-box/config.json)

        echo -e "${CYAN}${country_code} [ss2022][shadow-tls-v3]${NC} = ${PINK}ss, ${primary_ip}, ${shadowtls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true, udp-port=${ss_internal_port}${NC}"
        
        echo -e "\n${YELLOW}--- Optional: Direct Shadowsocks Node (for local network access to the SS port or other uses) ---${NC}"
        echo -e "${CYAN}${country_code} [ss2022]${NC} = ${PINK}ss, ${primary_ip}, ${ss_internal_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
    else
        # ShadowTLS not installed, Shadowsocks is listening on a public port
        local ss_public_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .listen_port' /etc/sing-box/config.json)
        echo -e "${CYAN}${country_code} [ss2022]${NC} = ${PINK}ss, ${primary_ip}, ${ss_public_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
    fi
    
    echo -e "\n${YELLOW}Note: Adapt to your client if it uses a different naming convention or parameters.${NC}"
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
    echo -e "\n${BLUE}====== Starting Sing-Box Installation ======${NC}"
    get_ip_info 

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

    echo -e "\n${BLUE}--- Verifying/Setting up 'sing-box' User and Directories ---${NC}"
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

    echo -e "\n${BLUE}--- Initial Sing-Box Configuration ---${NC}"
    rm -f /etc/sing-box/config.json 

    install_shadowtls_option="yes" # Default
    read -p "$(echo -e "${YELLOW}Install ShadowTLS v3 (recommended for obfuscation)? (yes/no) [Default: yes]: ${NC}")" user_shadowtls_choice
    if [[ "$user_shadowtls_choice" =~ ^[nN]([oO])?$ ]]; then
        install_shadowtls_option="no"
        echo -e "${BLUE}ShadowTLS installation will be skipped.${NC}"
    else
        echo -e "${BLUE}ShadowTLS will be installed.${NC}"
    fi

    echo -e "\n${BLUE}--- ShadowSocks Settings ---${NC}"
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
    echo -e "${GREEN}Generated Shadowsocks password.${NC}"

    local shadowtls_pwd=""
    local port=""
    local ss_port="" # This will be internal if ShadowTLS is used, or public if SS only
    local proxysite=""
    local wildcard_sni=""
    local shadowtls_inbound_json_segment=""

    if [[ "$install_shadowtls_option" == "yes" ]]; then
        shadowtls_pwd=$(openssl rand -base64 32)
        echo -e "${GREEN}Generated ShadowTLS password.${NC}"

        echo -e "\n${BLUE}--- ShadowTLS Port Configuration ---${NC}"
        read -p "$(echo -e "${YELLOW}Set ShadowTLS listening port [10000-65535] (Enter for random): ${NC}")" port
        [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1)
        until [[ "$port" =~ ^[0-9]+$ && "$port" -ge 10000 && "$port" -le 65535 && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; do
            echo -e "${RED}Port $port is invalid, out of range [10000-65535], or already in use.${NC}"
            read -p "$(echo -e "${YELLOW}Set new ShadowTLS port [10000-65535] (Enter for random): ${NC}")" port
            [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1) && echo -e "${BLUE}Random port selected: $port${NC}"
        done
        echo -e "${GREEN}Using port $port for ShadowTLS.${NC}"

        # Internal port for Shadowsocks when ShadowTLS is used
        ss_port=$(shuf -i 10000-65535 -n 1)
        until [[ $ss_port != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port") ]]; do
            ss_port=$(shuf -i 10000-65535 -n 1)
        done
        echo -e "${GREEN}Using internal port $ss_port for Shadowsocks (detoured from ShadowTLS).${NC}"

        echo -e "\n${BLUE}--- ShadowTLS Handshake Settings ---${NC}"
        read -p "$(echo -e "${YELLOW}Set SNI (fake website domain) for ShadowTLS (e.g., weather-data.apple.com) (Enter for default: weather-data.apple.com): ${NC}")" proxysite
        [[ -z $proxysite ]] && proxysite="weather-data.apple.com"
        echo -e "${GREEN}Using SNI: $proxysite${NC}"

        echo -e "\n${YELLOW}Select ShadowTLS wildcard SNI mode:${NC}"
        echo -e "  ${CYAN}1) off: Disable wildcard SNI (strict SNI match)${NC}"
        echo -e "  ${CYAN}2) authed: Change target to SNI:443 for authenticated connections (Recommended)${NC}"
        echo -e "  ${CYAN}3) all: Change target to SNI:443 for all connections (less common)${NC}"
        read -p "$(echo -e "${YELLOW}Choose an option [1-3] (Default: 2): ${NC}")" wildcard_sni_choice
        case "$wildcard_sni_choice" in
            1) wildcard_sni="off" ;;
            3) wildcard_sni="all" ;;
            *) wildcard_sni="authed" ;; 
        esac
        echo -e "${GREEN}Using wildcard_sni mode: $wildcard_sni${NC}"
        
        shadowtls_inbound_json_segment='
        {
            "type": "shadowtls",
            "tag": "shadowtls-in",
            "listen": "::",
            "listen_port": '$port',
            "version": 3,
            "users": [
                {
                    "password": "'"$shadowtls_pwd"'"
                }
            ],
            "handshake": {
                "server": "'"$proxysite"'",
                "server_port": 443
            },
            "strict_mode": true,
            "wildcard_sni": "'"$wildcard_sni"'",
            "detour": "shadowsocks-in"
        },'
    else
        # ShadowTLS not installed, configure public port for Shadowsocks
        echo -e "\n${BLUE}--- Shadowsocks Port Configuration ---${NC}"
        read -p "$(echo -e "${YELLOW}Set Shadowsocks public listening port [10000-65535] (Enter for random): ${NC}")" ss_port
        [[ -z $ss_port ]] && ss_port=$(shuf -i 10000-65535 -n 1)
        until [[ "$ss_port" =~ ^[0-9]+$ && "$ss_port" -ge 10000 && "$ss_port" -le 65535 && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port") ]]; do
            echo -e "${RED}Port $ss_port is invalid, out of range [10000-65535], or already in use.${NC}"
            read -p "$(echo -e "${YELLOW}Set new Shadowsocks public port [10000-65535] (Enter for random): ${NC}")" ss_port
            [[ -z $ss_port ]] && ss_port=$(shuf -i 10000-65535 -n 1) && echo -e "${BLUE}Random port selected: $ss_port${NC}"
        done
        echo -e "${GREEN}Using public port $ss_port for Shadowsocks.${NC}"
    fi

    echo -e "\n${BLUE}--- DNS Strategy Configuration ---${NC}"
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
        echo -e "${YELLOW}Warning: IP v4/v6 availability unknown. Offering all network strategy options.${NC}"
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

    echo -e "\n${BLUE}--- Generating Configuration File ---${NC}"
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
                "server": "1.1.1.1",
                "detour": "direct"
            },
            {
                "tag": "dns_google",
                "type": "https",
                "server": "8.8.8.8",
                "detour": "direct"
            },
            {
                "tag": "dns_resolver",
                "type": "local"
            }
        ],
        "strategy": "$default_strategy",
        "independent_cache": true
    },
    "inbounds": [
        ${shadowtls_inbound_json_segment}
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": $ss_port,
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
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
                "action": "direct",
                "domain_resolver": {
                    "server": "dns_resolver",
                    "strategy": "ipv4_only"
                }
            },
            {
                "rule_set": ["geosite-netflix"],
                "action": "direct",
                "domain_resolver": {
                    "server": "dns_resolver",
                    "strategy": "ipv6_only"
                }
            },
            {
                "rule_set": ["geosite-disney"],
                "action": "direct",
                "domain_resolver": {
                    "server": "dns_resolver",
                    "strategy": "ipv6_only"
                }
            },
            {
                "rule_set": ["geosite-category-media"],
                "action": "direct",
                "domain_resolver": {
                    "server": "dns_resolver",
                    "strategy": "ipv6_only"
                }
            },
            {
                "rule_set": ["geosite-spotify"],
                "action": "direct",
                "domain_resolver": {
                    "server": "dns_resolver",
                    "strategy": "prefer_ipv4" 
                }
            },
            {
                "rule_set": ["geosite-google"],
                "action": "direct",
                "domain_resolver": {
                    "server": "dns_resolver",
                    "strategy": "ipv4_only"
                }
            },
            {
                "rule_set": ["geoip-cn", "geosite-cn"],
                "action": "direct"
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

    echo -e "\n${BLUE}--- Formatting and Validating Configuration ---${NC}"
    if ! format_config; then
        echo -e "${RED}Critical Error: Halting installation due to configuration error. Please check messages above.${NC}"
        echo -e "${YELLOW}The file /etc/sing-box/config.json may be invalid or an intermediate temp file might remain in /tmp/.${NC}"
        exit 1
    fi

    echo -e "\n${BLUE}--- Starting and Enabling Sing-Box Service ---${NC}"
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
    echo -e "\n${GREEN}====== Sing-Box Installation Complete ======${NC}"
}

# Function to uninstall Sing-Box
uninstall_sing_box() {
    echo -e "\n${RED}--- Uninstalling Sing-Box ---${NC}"
    read -p "$(echo -e "${YELLOW}Are you sure you want to uninstall Sing-Box and remove all its configurations? (yes/no): ${NC}")" confirmation
    if [[ "$confirmation" != "yes" ]]; then
        echo -e "${BLUE}Uninstallation cancelled.${NC}"
        return
    fi

    echo -e "${BLUE}Stopping Sing-Box service...${NC}"
    systemctl stop sing-box
    echo -e "${BLUE}Disabling Sing-Box service...${NC}"
    systemctl disable sing-box
    echo -e "${BLUE}Removing Sing-Box package (apt autoremove sing-box)...${NC}"
    apt autoremove --purge sing-box -y 
    echo -e "${BLUE}Removing residual directories (/etc/sing-box, /var/lib/sing-box)...${NC}"
    rm -rf /etc/sing-box /var/lib/sing-box 
    echo -e "${GREEN}Sing-Box has been uninstalled.${NC}"
}

# Function to start Sing-Box service
start_sing_box() {
    echo -e "${BLUE}Starting Sing-Box service...${NC}"
    systemctl start sing-box
    systemctl enable sing-box >/dev/null 2>&1 
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Sing-Box service started successfully.${NC}"
    else
        echo -e "${RED}Error: Failed to start Sing-Box service.${NC}"
        echo -e "${YELLOW}Check status: systemctl status sing-box${NC}"
    fi
}

# Function to stop Sing-Box service
stop_sing_box() {
    echo -e "${BLUE}Stopping Sing-Box service...${NC}"
    systemctl stop sing-box
    if ! systemctl is-active --quiet sing-box; then
        echo -e "${YELLOW}Sing-Box service stopped.${NC}"
    else
        echo -e "${RED}Error: Failed to stop Sing-Box service.${NC}"
    fi
}

# Function to restart Sing-Box service
restart_sing_box() {
    echo -e "${BLUE}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Sing-Box service restarted successfully.${NC}"
    else
        echo -e "${RED}Error: Failed to restart Sing-Box service.${NC}"
        echo -e "${YELLOW}Check status: systemctl status sing-box${NC}"
    fi
}

# Function to manage Sing-Box service
manage_sing_box() {
    if ! command -v sing-box >/dev/null 2>&1; then
        echo -e "${RED}Sing-Box is not installed. Please install it first.${NC}"
        return
    fi
    while true; do
        echo -e "\n${YELLOW}--- Manage Sing-Box Service ---${NC}"
        echo -e "Service status: $(systemctl is-active sing-box && echo -e "${GREEN}Active${NC}" || echo -e "${RED}Inactive${NC}")"
        echo -e "Enabled on boot: $(systemctl is-enabled sing-box && echo -e "${GREEN}Yes${NC}" || echo -e "${RED}No${NC}")"
        echo -e "\n${YELLOW}Select an operation:${NC}"
        echo -e "  ${CYAN}1) Start Service${NC}"
        echo -e "  ${CYAN}2) Stop Service${NC}"
        echo -e "  ${CYAN}3) Restart Service${NC}"
        echo -e "  ${CYAN}4) Enable Service on Boot${NC}"
        echo -e "  ${CYAN}5) Disable Service on Boot${NC}"
        echo -e "  ${CYAN}6) View Service Status (systemctl status)${NC}"
        echo -e "  ${CYAN}7) View Service Logs (journalctl)${NC}"
        echo -e "  ${CYAN}0) Return to Main Menu${NC}"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-7]: ${NC}")" switchInput
        case $switchInput in
            1 ) start_sing_box ;;
            2 ) stop_sing_box ;;
            3 ) restart_sing_box ;;
            4 ) systemctl enable sing-box && echo -e "${GREEN}Sing-Box enabled on boot.${NC}" || echo -e "${RED}Failed to enable Sing-Box.${NC}" ;;
            5 ) systemctl disable sing-box && echo -e "${YELLOW}Sing-Box disabled on boot.${NC}" || echo -e "${RED}Failed to disable Sing-Box.${NC}" ;;
            6 ) systemctl status sing-box ;;
            7 ) journalctl -u sing-box -e --no-pager ;; 
            0 ) return ;;
            * ) echo -e "${RED}Invalid choice. Please try again.${NC}" ;;
        esac
        [[ "$switchInput" != "0" ]] && read -p "$(echo -e "\n${BLUE}Press Enter to continue...${NC}")"
    done
}

# Function to change ShadowTLS port
change_port() {
    echo -e "\n${BLUE}--- Change ShadowTLS Port ---${NC}"
    if ! jq -e 'any(.inbounds[]; .type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; then
        echo -e "${RED}Error: ShadowTLS is not configured. This option is not applicable.${NC}"
        return
    fi
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi
    
    local oldport=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .listen_port' /etc/sing-box/config.json)
    echo -e "${BLUE}Current ShadowTLS port: ${CYAN}$oldport${NC}"
    
    read -p "$(echo -e "${YELLOW}Set new ShadowTLS port [10000-65535] (Enter for random, current: $oldport): ${NC}")" port
    if [[ -z "$port" ]]; then
        port=$(shuf -i 10000-65535 -n 1)
        echo -e "${BLUE}Random port selected: $port${NC}"
    fi

    until [[ "$port" =~ ^[0-9]+$ && "$port" -ge 10000 && "$port" -le 65535 && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED}Port $port is invalid, out of range [10000-65535], or already in use.${NC}"
        read -p "$(echo -e "${YELLOW}Set new ShadowTLS port [10000-65535] (Enter for random): ${NC}")" port
        [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1) && echo -e "${BLUE}Random port selected: $port${NC}"
    done
    echo -e "${GREEN}Using new port $port for ShadowTLS.${NC}"

    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_port
    jq --argjson newport "$port" '(.inbounds[] | select(.type == "shadowtls") | .listen_port) = $newport' /etc/sing-box/config.json.bak_port > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Sing-Box ShadowTLS port has been changed to: $port${NC}"
            echo -e "${YELLOW}Please update your client configuration file.${NC}"
            output_node_info
            rm /etc/sing-box/config.json.bak_port 
        else
            echo -e "${RED}Error: Port update failed due to configuration error after change. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_port /etc/sing-box/config.json
            restart_sing_box 
        fi
    else
        echo -e "${RED}Error: Failed to update port in JSON structure using jq.${NC}"
        rm -f /tmp/config.json.tmp
    fi
}

# Function to change passwords (ShadowTLS & Shadowsocks)
change_passwords() {
    echo -e "\n${BLUE}--- Reset Passwords ---${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi

    has_shadowtls_inbound_for_passwd=$(jq -e 'any(.inbounds[]; .type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1 && echo "true" || echo "false")
    local new_shadowtls_pwd=""
    local jq_script=""

    if [[ "$has_shadowtls_inbound_for_passwd" == "true" ]]; then
        local old_shadowtls_pwd=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .users[0].password' /etc/sing-box/config.json)
        new_shadowtls_pwd=$(openssl rand -base64 32)
        echo -e "${BLUE}New ShadowTLS password will be generated.${NC}"
    fi
    
    local old_ss_pwd=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .password' /etc/sing-box/config.json)
    local new_ss_pwd
    local current_ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json)
    case "$current_ss_method" in
        "2022-blake3-aes-128-gcm") new_ss_pwd=$(openssl rand -base64 16) ;;
        *) new_ss_pwd=$(openssl rand -base64 32) ;;
    esac
    echo -e "${BLUE}New Shadowsocks password will be generated.${NC}"

    echo -e "${BLUE}Updating passwords in configuration file...${NC}"
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_passwd

    if [[ "$has_shadowtls_inbound_for_passwd" == "true" ]]; then
        jq_script='((.inbounds[] | select(.type == "shadowtls") | .users[0]).password) = $new_stls_pwd | ((.inbounds[] | select(.tag == "shadowsocks-in")).password) = $new_ss_pwd'
        jq --arg new_stls_pwd "$new_shadowtls_pwd" --arg new_ss_pwd "$new_ss_pwd" "$jq_script" /etc/sing-box/config.json.bak_passwd > /tmp/config.json.tmp
    else
        jq_script='((.inbounds[] | select(.tag == "shadowsocks-in")).password) = $new_ss_pwd'
        jq --arg new_ss_pwd "$new_ss_pwd" "$jq_script" /etc/sing-box/config.json.bak_passwd > /tmp/config.json.tmp
    fi
    

    if [[ $? -eq 0 && -s /tmp/config.json.tmp ]]; then # Check if jq command succeeded and output file is not empty
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Sing-Box passwords have been reset.${NC}"
            echo -e "${YELLOW}Please update your client configuration file.${NC}"
            output_node_info
            rm /etc/sing-box/config.json.bak_passwd
        else
            echo -e "${RED}Error: Password update failed due to configuration error. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_passwd /etc/sing-box/config.json
            restart_sing_box 
        fi
    else
        echo -e "${RED}Error: Failed to update passwords in JSON structure using jq.${NC}"
        rm -f /tmp/config.json.tmp
    fi
}

# Function to change Shadowsocks encryption method
change_ss_method() {
    echo -e "\n${BLUE}--- Change Shadowsocks Encryption Method ---${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi

    local old_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json)
    echo -e "${BLUE}Current Shadowsocks encryption method: ${CYAN}$old_method${NC}"
    
    echo -e "\n${YELLOW}Select new Shadowsocks encryption method:${NC}"
    echo -e "  ${CYAN}1) 2022-blake3-aes-128-gcm${NC}"
    echo -e "  ${CYAN}2) 2022-blake3-aes-256-gcm${NC}"
    echo -e "  ${CYAN}3) 2022-blake3-chacha20-poly1305${NC}"
    echo -e "  ${CYAN}4) aes-128-gcm${NC}"
    echo -e "  ${CYAN}5) aes-256-gcm${NC}"
    echo -e "  ${CYAN}6) chacha20-ietf-poly1305${NC}"
    echo -e "  ${CYAN}0) Cancel${NC}"
    read -p "$(echo -e "${YELLOW}Enter your choice [0-6]: ${NC}")" ss_method_choice
    local new_method=""
    case "$ss_method_choice" in
        1) new_method="2022-blake3-aes-128-gcm" ;;
        2) new_method="2022-blake3-aes-256-gcm" ;;
        3) new_method="2022-blake3-chacha20-poly1305" ;;
        4) new_method="aes-128-gcm" ;;
        5) new_method="aes-256-gcm" ;;
        6) new_method="chacha20-ietf-poly1305" ;;
        0) echo -e "${BLUE}Cancelled.${NC}"; return ;;
        *) echo -e "${RED}Invalid choice.${NC}"; return ;;
    esac

    if [[ "$new_method" == "$old_method" ]]; then
        echo -e "${YELLOW}Selected method is the same as current. No changes made.${NC}"
        return
    fi

    echo -e "${BLUE}Changing method to $new_method and generating a new compatible password...${NC}"
    local new_ss_pwd
    case "$new_method" in
        "2022-blake3-aes-128-gcm") new_ss_pwd=$(openssl rand -base64 16) ;;
        *) new_ss_pwd=$(openssl rand -base64 32) ;;
    esac

    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_ssmethod
    jq --arg new_m "$new_method" --arg new_p "$new_ss_pwd" \
        '((.inbounds[] | select(.type == "shadowsocks")).method) = $new_m |'
        '((.inbounds[] | select(.type == "shadowsocks")).password) = $new_p'
    /etc/sing-box/config.json.bak_ssmethod > /tmp/config.json.tmp

    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Shadowsocks encryption method changed to: $new_method${NC}"
            echo -e "${GREEN}A new password has also been generated for this method.${NC}"
            echo -e "${YELLOW}Please update your client configuration file.${NC}"
            output_node_info
            rm /etc/sing-box/config.json.bak_ssmethod
        else
            echo -e "${RED}Error: Method change failed due to configuration error. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_ssmethod /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to update method/password in JSON using jq.${NC}"
        rm -f /tmp/config.json.tmp
    fi
}

# Function to change routing preferences (DNS strategy for specific services)
change_routing_preferences() {
    echo -e "\n${BLUE}--- Change Service-Specific DNS Strategy ---${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi
    get_ip_info 

    local services_map=(
        "AI Chat (!CN)|geosite-ai-chat-!cn"
        "Google|geosite-google"
        "Netflix|geosite-netflix"
        "Disney|geosite-disney"
        "Spotify|geosite-spotify"
        "General Media (category)|geosite-category-media"
        "All GeoSite Rules (Use with caution)|all_geosites" 
    )
    
    local available_strategies=()
    if [[ $has_ipv4 -eq 1 && $has_ipv6 -eq 1 ]]; then
        available_strategies=("prefer_ipv4" "prefer_ipv6" "ipv4_only" "ipv6_only")
    elif [[ $has_ipv4 -eq 1 ]]; then
        available_strategies=("ipv4_only" "prefer_ipv4")
    elif [[ $has_ipv6 -eq 1 ]]; then
        available_strategies=("ipv6_only" "prefer_ipv6")
    else
        echo -e "${YELLOW}Warning: IP v4/v6 availability unknown. Offering all network strategy options.${NC}"
        available_strategies=("prefer_ipv4" "prefer_ipv6" "ipv4_only" "ipv6_only")
    fi 

    if [[ ${#available_strategies[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No network strategies available for configuration. Returning.${NC}"
        return
    fi

    while true; do
        echo -e "\n${YELLOW}Select a service category to modify its DNS strategy:${NC}"
        for i in "${!services_map[@]}"; do
            local display_name=$(echo "${services_map[$i]}" | cut -d'|' -f1)
            local current_strategy_display=""
            local rule_set_tag_jq=$(echo "${services_map[$i]}" | cut -d'|' -f2)

            if [[ "$rule_set_tag_jq" != "all_geosites" ]]; then
                 current_strategy=$(jq -r --arg rs "$rule_set_tag_jq" '.route.rules[] | select(.rule_set != null and .rule_set[0] == $rs) | .domain_resolver.strategy // "N/A"' /etc/sing-box/config.json)
                 current_strategy_display=" (Current: ${CYAN}${current_strategy}${NC})"
            fi
            echo -e "  ${CYAN}$((i+1))) ${display_name}${current_strategy_display}${NC}"
        done
        echo -e "  ${CYAN}0) Return to Previous Menu${NC}"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-${#services_map[@]}]: ${NC}")" service_choice

        if ! [[ "$service_choice" =~ ^[0-9]+$ ]] || [[ "$service_choice" -lt 0 || "$service_choice" -gt ${#services_map[@]} ]]; then
            echo -e "${RED}Invalid choice. Try again.${NC}"
            continue
        fi
        if [[ $service_choice -eq 0 ]]; then return; fi

        local selected_service_entry=${services_map[$((service_choice-1))]}
        local service_display_name=$(echo "$selected_service_entry" | cut -d'|' -f1)
        local rule_set_tag=$(echo "$selected_service_entry" | cut -d'|' -f2)
            
        echo -e "\n${YELLOW}Select DNS strategy for '${service_display_name}':${NC}"
        for i in "${!available_strategies[@]}"; do
            echo -e "  ${CYAN}$((i+1))) ${available_strategies[$i]}${NC}"
        done
        echo -e "  ${CYAN}0) Cancel this change${NC}"
        read -p "$(echo -e "${YELLOW}Enter strategy choice [0-${#available_strategies[@]}]: ${NC}")" strategy_choice_idx

        if ! [[ "$strategy_choice_idx" =~ ^[0-9]+$ ]] || [[ "$strategy_choice_idx" -lt 0 || "$strategy_choice_idx" -gt ${#available_strategies[@]} ]]; then
            echo -e "${RED}Invalid strategy choice. Try again.${NC}"
            continue
        fi
        if [[ $strategy_choice_idx -eq 0 ]]; then echo -e "${BLUE}Cancelled change for ${service_display_name}.${NC}"; continue; fi

        local selected_strategy=${available_strategies[$((strategy_choice_idx-1))]}
        
        cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_routing
        local jq_query
        if [[ "$rule_set_tag" == "all_geosites" ]]; then
            echo -e "${YELLOW}Applying strategy '${selected_strategy}' to ALL rules containing 'rule_set' field...${NC}"
            jq_query='
                .route.rules |= map(
                    if (.rule_set != null) then
                        .domain_resolver = {"server": "dns_resolver", "strategy": $new_strategy}
                    else . end
                )'
        else
            jq_query='
                .route.rules |= map(
                    if (.rule_set != null and .rule_set[0] == $rs_tag) then
                         .domain_resolver = {"server": "dns_resolver", "strategy": $new_strategy}
                    else . end
                )'
        fi

        jq --arg rs_tag "$rule_set_tag" --arg new_strategy "$selected_strategy" "$jq_query" \
            /etc/sing-box/config.json.bak_routing > /tmp/config.json.tmp

        if [[ $? -eq 0 ]]; then
            mv /tmp/config.json.tmp /etc/sing-box/config.json
            echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
            if format_config; then
                echo -e "${GREEN}Successfully updated DNS strategy for '${service_display_name}' to '${selected_strategy}'.${NC}"
                systemctl restart sing-box
                echo -e "\n${YELLOW}Current configuration snippet for '${service_display_name}':${NC}"
                if [[ "$rule_set_tag" == "all_geosites" ]]; then
                    jq '.route.rules[] | select(.rule_set != null and .domain_resolver.strategy == $strat)' --arg strat "$selected_strategy" /etc/sing-box/config.json
                else
                    jq '.route.rules[] | select(.rule_set != null and .rule_set[0] == $rs)' --arg rs "$rule_set_tag" /etc/sing-box/config.json
                fi
                rm /etc/sing-box/config.json.bak_routing
            else
                echo -e "${RED}Error: Strategy update failed due to configuration error. Restoring backup...${NC}"
                mv /etc/sing-box/config.json.bak_routing /etc/sing-box/config.json
                restart_sing_box
            fi
        else
            echo -e "${RED}Error: Failed to update routing strategy using jq.${NC}"
            rm -f /tmp/config.json.tmp
        fi
        read -p "$(echo -e "\n${BLUE}Press Enter to continue...${NC}")"
    done
}

# Function to change ShadowTLS wildcard SNI mode
change_wildcard_sni() {
    echo -e "\n${BLUE}--- Change ShadowTLS Wildcard SNI Mode ---${NC}"
    if ! jq -e 'any(.inbounds[]; .type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; then
        echo -e "${RED}Error: ShadowTLS is not configured. This option is not applicable.${NC}"
        return
    fi
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi

    local current_wildcard_sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .wildcard_sni // "not set"' /etc/sing-box/config.json)
    echo -e "${BLUE}Current wildcard SNI mode: ${CYAN}$current_wildcard_sni${NC}"
    
    echo -e "\n${YELLOW}Select new ShadowTLS wildcard SNI mode:${NC}"
    echo -e "  ${CYAN}1) off: Disable wildcard SNI (strict SNI match)${NC}"
    echo -e "  ${CYAN}2) authed: Change target to SNI:443 for authenticated connections (Recommended)${NC}"
    echo -e "  ${CYAN}3) all: Change target to SNI:443 for all connections (less common)${NC}"
    echo -e "  ${CYAN}0) Cancel${NC}"
    read -p "$(echo -e "${YELLOW}Choose an option [0-3] (Enter to keep current: $current_wildcard_sni): ${NC}")" wildcard_sni_choice
    
    local new_wildcard_sni=""
    case "$wildcard_sni_choice" in
        1) new_wildcard_sni="off" ;;
        2) new_wildcard_sni="authed" ;;
        3) new_wildcard_sni="all" ;;
        0) echo -e "${BLUE}Cancelled.${NC}"; return ;;
        "") echo -e "${YELLOW}No change. Keeping current setting: $current_wildcard_sni${NC}"; return ;;
        *) echo -e "${RED}Invalid choice.${NC}"; return ;;
    esac
    
    if [[ "$new_wildcard_sni" == "$current_wildcard_sni" ]]; then
        echo -e "${YELLOW}Selected mode is the same as current. No changes made.${NC}"
        return
    fi

    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_sni
    jq --arg sni "$new_wildcard_sni" '(.inbounds[] | select(.type == "shadowtls")).wildcard_sni = $sni' /etc/sing-box/config.json.bak_sni > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            echo -e "${GREEN}Wildcard SNI mode changed to: $new_wildcard_sni${NC}"
            restart_sing_box
            rm /etc/sing-box/config.json.bak_sni
        else
            echo -e "${RED}Error: Wildcard SNI update failed due to configuration error. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_sni /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to update wildcard SNI using jq.${NC}"
        rm -f /tmp/config.json.tmp
    fi
}

# Function to modify Sing-Box configuration
modify_configuration() {
    if ! command -v sing-box >/dev/null 2>&1 || [ ! -f /etc/sing-box/config.json ]; then
        echo -e "${RED}Sing-Box is not installed or config file is missing. Please install/reinstall it first.${NC}"
        return
    fi
    while true; do
        echo -e "\n${GREEN}--- Modify Sing-Box Configuration ---${NC}"
        echo -e "${YELLOW}Select an option to change:${NC}"
        echo -e "  ${CYAN}1) Change ShadowTLS Port${NC}"
        echo -e "  ${CYAN}2) Reset Passwords${NC}"
        echo -e "  ${CYAN}3) Change Shadowsocks Encryption Method${NC}"
        echo -e "  ${CYAN}4) Change Service-Specific DNS Strategy${NC}"
        echo -e "  ${CYAN}5) Change ShadowTLS Wildcard SNI Mode${NC}"
        echo -e "  ${CYAN}0) Return to Main Menu${NC}"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-5]: ${NC}")" confAnswer
        case $confAnswer in
            1 ) 
                if ! jq -e 'any(.inbounds[]; .type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; then
                    echo -e "${RED}ShadowTLS is not installed. This option is unavailable.${NC}"
                else 
                    change_port 
                fi 
                ;;
            2 ) change_passwords ;;
            3 ) change_ss_method ;;
            4 ) change_routing_preferences ;;
            5 ) 
                if ! jq -e 'any(.inbounds[]; .type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; then
                    echo -e "${RED}ShadowTLS is not installed. This option is unavailable.${NC}"
                else
                    change_wildcard_sni
                fi
                ;;
            0 ) return ;;
            * ) echo -e "${RED}Invalid choice. Please try again.${NC}" ;;
        esac
        [[ "$confAnswer" != "0" ]] && read -p "$(echo -e "\n${BLUE}Press Enter to continue...${NC}")"
    done
}

# Function to show current configuration (node info)
show_configuration() {
    if ! command -v sing-box >/dev/null 2>&1 || [ ! -f /etc/sing-box/config.json ]; then
        echo -e "${RED}Sing-Box is not installed or config file is missing. Please install it first.${NC}"
        return
    fi
    output_node_info
}

# Main menu function
menu() {
    while true; do
        clear
        echo -e "${MAGENTA}┌─────────────────────────────────────────┐${NC}"
        echo -e "${MAGENTA}│   ShadowTLS + Shadowsocks Manager       │${NC}"
        echo -e "${MAGENTA}│          Powered by Sing-Box            │${NC}"
        echo -e "${MAGENTA}└─────────────────────────────────────────┘${NC}"
        echo -e "----------------------------------------"
        echo -e "${GREEN}  1) Install Sing-Box${NC}"
        echo -e "${GREEN}  2) Uninstall Sing-Box${NC}"
        echo -e "${GREEN}  3) Manage Sing-Box Service${NC}"
        echo -e "${GREEN}  4) Modify Configuration${NC}"
        echo -e "${GREEN}  5) Display Node Information${NC}"
        echo -e "${RED}  0) Exit Script${NC}"
        echo -e "----------------------------------------"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-5]: ${NC}")" choice

        case "$choice" in
            1) install_sing_box ;;
            2) uninstall_sing_box ;;
            3) manage_sing_box ;;
            4) modify_configuration ;;
            5) show_configuration ;;
            0) echo -e "${BLUE}Exiting script. Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
        esac
        [[ "$choice" != "0" ]] && read -p "$(echo -e "\n${BLUE}Press Enter to return to the main menu...${NC}")"
    done
}

# --- Main script execution ---
trap 'echo -e "${RED}\nScript interrupted. Exiting cleanly.${NC}"; rm -f /tmp/config.json.* /etc/sing-box/config.json.bak_*; exit 1' INT TERM
clear
echo -e "${BLUE}Welcome to the ShadowTLS + Shadowsocks Manager Script!${NC}"

check_root
check_system
install_dependencies 

menu

exit 0
