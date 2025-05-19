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
last_added_outbound_tag="" # Used by modify_outbound

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
    echo -e "\n${YELLOW}--- Generated Node Information ---${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then
        echo -e "${RED}Error: Configuration file /etc/sing-box/config.json not found.${NC}"
        return 1
    fi

    local ss_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .listen_port' /etc/sing-box/config.json)
    local ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json)
    local ss_pwd=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .password' /etc/sing-box/config.json)
    
    if [[ -z "$country_code" ]]; then 
        get_ip_info 
    fi

    # Check if ShadowTLS inbound exists
    local shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)

    if [[ "$shadowtls_inbound_exists" -eq 0 ]]; then # ShadowTLS exists
        local stls_port=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .listen_port' /etc/sing-box/config.json)
        local shadowtls_pwd=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .users[0].password' /etc/sing-box/config.json)
        local sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)
        
        # For SS+ShadowTLS, primary_ip is the server IP, stls_port is the main port
        # ss_port is internal and used in the udp-port parameter if needed by client.
        echo -e "${CYAN}${country_code}${NC} (SS+ShadowTLS) = ${PINK}ss://${primary_ip}:${stls_port}?encrypt-method=${ss_method}&password=${ss_pwd}&shadow-tls-password=${shadowtls_pwd}&shadow-tls-sni=${sni}&shadow-tls-version=3&udp-relay=true&udp-port=${ss_port}${NC}"
        echo -e "\n${YELLOW}Note: This is a pseudo-URL format for easy parsing. Adapt to your client's format.${NC}"
    else # Shadowsocks Only
        # For SS Only, ss_port is the main listening port
        # Construct a simple SS URI
        local ss_uri_part="${ss_method}:${ss_pwd}@${primary_ip}:${ss_port}"
        local ss_uri_encoded=$(echo -n "$ss_uri_part" | base64 | tr -d '\n')
        echo -e "${CYAN}${country_code}${NC} (SS Only) = ${PINK}ss://${ss_uri_encoded}${NC}"
        echo -e "\n${YELLOW}Shadowsocks URI: ss://${ss_uri_encoded}${NC}"
        echo -e "${YELLOW}Parameters for manual configuration:${NC}"
        echo -e "  ${CYAN}Server Address: ${NC}${primary_ip}"
        echo -e "  ${CYAN}Server Port: ${NC}${ss_port}"
        echo -e "  ${CYAN}Password: ${NC}${ss_pwd}"
        echo -e "  ${CYAN}Encryption Method: ${NC}${ss_method}"
    fi
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

    local installation_type=""
    echo -e "\n${YELLOW}Select Installation Type:${NC}"
    echo -e "  ${CYAN}1) Shadowsocks + ShadowTLS (Recommended for obfuscation)${NC}"
    echo -e "  ${CYAN}2) Shadowsocks Only (Simpler setup, less obfuscation)${NC}"
    echo -e "  ${CYAN}0) Cancel Installation${NC}"
    read -p "$(echo -e "${YELLOW}Enter your choice [0-2] (Default: 1): ${NC}")" type_choice

    case "$type_choice" in
        2) installation_type="ss_only" ;;
        0) echo -e "${BLUE}Installation cancelled.${NC}"; return ;;
        *) installation_type="ss_shadowtls" ;;
    esac
    echo -e "${GREEN}Selected installation type: $installation_type${NC}"

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
    local proxysite=""
    local wildcard_sni=""

    if [[ "$installation_type" == "ss_shadowtls" ]]; then
        shadowtls_pwd=$(openssl rand -base64 32)
        echo -e "${GREEN}Generated ShadowTLS password.${NC}"

        echo -e "\n${BLUE}--- Port Configuration (ShadowTLS) ---${NC}"
        read -p "$(echo -e "${YELLOW}Set ShadowTLS listening port [10000-65535] (Enter for random): ${NC}")" port
        [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1)
        until [[ "$port" =~ ^[0-9]+$ && "$port" -ge 10000 && "$port" -le 65535 && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; do
            echo -e "${RED}Port $port is invalid, out of range [10000-65535], or already in use.${NC}"
            read -p "$(echo -e "${YELLOW}Set new ShadowTLS port [10000-65535] (Enter for random): ${NC}")" port
            [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1) && echo -e "${BLUE}Random port selected: $port${NC}"
        done
        echo -e "${GREEN}Using new port $port for ShadowTLS.${NC}"
    fi

    # SS port is always needed, but its role might differ slightly
    # If ShadowTLS is used, SS port is internal. If SS only, it's the main listening port.
    echo -e "\n${BLUE}--- Port Configuration (Shadowsocks) ---${NC}"
    local ss_listen_desc="Set Shadowsocks listening port"
    if [[ "$installation_type" == "ss_shadowtls" ]]; then
      ss_listen_desc="Set Shadowsocks internal listening port (detoured from ShadowTLS)"
    fi
    read -p "$(echo -e "${YELLOW}${ss_listen_desc} [10000-65535] (Enter for random): ${NC}")" ss_port
    [[ -z $ss_port ]] && ss_port=$(shuf -i 10000-65535 -n 1)
    # Ensure SS port is different from ShadowTLS port if ShadowTLS is active
    local port_check_cmd="ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w \"$ss_port\""
    until [[ "$ss_port" =~ ^[0-9]+$ && "$ss_port" -ge 10000 && "$ss_port" -le 65535 && ( "$installation_type" == "ss_only" || "$ss_port" -ne "$port" ) && -z $(eval $port_check_cmd) ]]; do
        echo -e "${RED}Port $ss_port is invalid, out of range, already in use, or conflicts with ShadowTLS port $port.${NC}"
        read -p "$(echo -e "${YELLOW}${ss_listen_desc} [10000-65535] (Enter for random): ${NC}")" ss_port
        [[ -z $ss_port ]] && ss_port=$(shuf -i 10000-65535 -n 1) && echo -e "${BLUE}Random port selected: $ss_port${NC}"
    done
    echo -e "${GREEN}Using port $ss_port for Shadowsocks.${NC}"

    if [[ "$installation_type" == "ss_shadowtls" ]]; then
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

    echo -e "\n${BLUE}--- Generating Configuration File ---${NC}"
    
    local inbounds_json=""
    if [[ "$installation_type" == "ss_shadowtls" ]]; then
        inbounds_json=$(cat <<EOF
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
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": $ss_port,
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
EOF
)
    else # ss_only
        inbounds_json=$(cat <<EOF
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": $ss_port,
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
EOF
)
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
                "action": "direct",
                "domain_resolver": {
                    "server": "dns_resolver",
                    "strategy": "ipv4_only"
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
                "rule_set": ["geoip-cn", "geosite-cn"],
                "action": "reject"
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
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi

    # Check if ShadowTLS inbound exists
    local shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    if [[ "$shadowtls_inbound_exists" -ne 0 ]]; then
        echo -e "${YELLOW}ShadowTLS is not configured for this installation. This option is not applicable.${NC}"
        echo -e "${YELLOW}If you want to change the Shadowsocks port, please reinstall or manually edit the configuration.${NC}"
        return
    fi
    
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

    # Check if ShadowTLS inbound exists
    local shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)

    local new_ss_pwd
    local current_ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json)
    case "$current_ss_method" in
        "2022-blake3-aes-128-gcm") new_ss_pwd=$(openssl rand -base64 16) ;;
        *) new_ss_pwd=$(openssl rand -base64 32) ;;
    esac
    echo -e "${GREEN}Generated new Shadowsocks password.${NC}"

    local new_shadowtls_pwd=""
    local temp_config_file="/tmp/config.json.tmp.$$"

    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_passwd
    cp /etc/sing-box/config.json "$temp_config_file"

    # Update Shadowsocks password first
    jq --arg new_ss_p "$new_ss_pwd" 
       '(.inbounds[] | select(.type == "shadowsocks")).password = $new_ss_p' 
       "$temp_config_file" > "$temp_config_file.updated_ss"
    
    if [[ $? -ne 0 ]]; then
        echo "${RED}Error updating Shadowsocks password with jq.${NC}"
        rm -f "$temp_config_file" "$temp_config_file.updated_ss"
        return
    fi
    mv "$temp_config_file.updated_ss" "$temp_config_file"

    if [[ "$shadowtls_inbound_exists" -eq 0 ]]; then # ShadowTLS exists
        echo -e "${BLUE}(ShadowTLS & Shadowsocks passwords will be reset)${NC}"
        new_shadowtls_pwd=$(openssl rand -base64 32)
        echo -e "${GREEN}Generated new ShadowTLS password.${NC}"
        
        jq --arg new_stls_p "$new_shadowtls_pwd" 
           '(.inbounds[] | select(.type == "shadowtls") | .users[0]).password = $new_stls_p' 
           "$temp_config_file" > "$temp_config_file.updated_stls"

        if [[ $? -ne 0 ]]; then
            echo "${RED}Error updating ShadowTLS password with jq.${NC}"
            rm -f "$temp_config_file" "$temp_config_file.updated_stls"
            # Restore original SS password if STLS update fails mid-way might be complex here, 
            # For now, we proceed with SS password changed, or restore the whole backup.
            return
        fi
        mv "$temp_config_file.updated_stls" "$temp_config_file"
    else 
        echo -e "${BLUE}(Only Shadowsocks password will be reset)${NC}"
    fi

    echo -e "${BLUE}Updating passwords in configuration file...${NC}"
    
    # $temp_config_file now contains all updates
    mv "$temp_config_file" /etc/sing-box/config.json 
    
    echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
    if format_config; then # format_config uses /etc/sing-box/config.json
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
    # Ensure temp files are cleaned up in any case, though mv should handle the main one.
    rm -f "$temp_config_file" "$temp_config_file.updated_ss" "$temp_config_file.updated_stls"
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
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi

    # Check if ShadowTLS inbound exists
    local shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    if [[ "$shadowtls_inbound_exists" -ne 0 ]]; then
        echo -e "${YELLOW}ShadowTLS is not configured for this installation. This option is not applicable.${NC}"
        return
    fi

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
        echo -e "  ${CYAN}2) Reset Passwords (ShadowTLS & Shadowsocks)${NC}"
        echo -e "  ${CYAN}3) Change Shadowsocks Encryption Method${NC}"
        echo -e "  ${CYAN}4) Change Service-Specific DNS Strategy${NC}"
        echo -e "  ${CYAN}5) Change ShadowTLS Wildcard SNI Mode${NC}"
        echo -e "  ${CYAN}0) Return to Main Menu${NC}"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-5]: ${NC}")" confAnswer
        case $confAnswer in
            1 ) change_port ;;
            2 ) change_passwords ;;
            3 ) change_ss_method ;;
            4 ) change_routing_preferences ;;
            5 ) change_wildcard_sni ;;
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

# Function to manage outbound connections
manage_outbounds() {
    if ! command -v sing-box >/dev/null 2>&1 || [ ! -f /etc/sing-box/config.json ]; then
        echo -e "${RED}Sing-Box is not installed or config file is missing. Please install it first.${NC}"
        return
    fi
    
    while true; do
        echo -e "\n${YELLOW}--- Manage Outbound Connections ---${NC}"
        
        # Get current outbounds
        local outbounds=$(jq -r '.outbounds[] | .tag + " (" + .type + ")"' /etc/sing-box/config.json 2>/dev/null)
        if [[ -z "$outbounds" ]]; then
            echo -e "${RED}Error: Failed to parse outbounds or none defined. Using default 'direct' outbound.${NC}"
            outbounds="direct (direct)"
        fi
        
        echo -e "${BLUE}Current Outbound Connections:${NC}"
        echo -e "$outbounds" | nl -w2 -s') '
        
        echo -e "\n${YELLOW}Select an operation:${NC}"
        echo -e "  ${CYAN}1) Add New Outbound Connection${NC}"
        echo -e "  ${CYAN}2) Remove Outbound Connection${NC}"
        echo -e "  ${CYAN}3) Modify Outbound Connection${NC}"
        echo -e "  ${CYAN}0) Return to Main Menu${NC}"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-3]: ${NC}")" outbound_choice
        
        case $outbound_choice in
            1) add_outbound ;;
            2) remove_outbound ;;
            3) modify_outbound ;;
            0) return ;;
            *) echo -e "${RED}Invalid choice. Please try again.${NC}" ;;
        esac
        
        [[ "$outbound_choice" != "0" ]] && read -p "$(echo -e "\n${BLUE}Press Enter to continue...${NC}")"
    done
}

# Function to add a new outbound connection
add_outbound() {
    echo -e "\n${BLUE}--- Add New Outbound Connection ---${NC}"
    
    echo -e "${YELLOW}Select outbound type:${NC}"
    echo -e "  ${CYAN}1) Direct${NC}"
    echo -e "  ${CYAN}2) Block${NC}"
    echo -e "  ${CYAN}3) Shadowsocks${NC}"
    echo -e "  ${CYAN}4) ShadowTLS${NC}"
    echo -e "  ${CYAN}5) Trojan${NC}"
    echo -e "  ${CYAN}6) AnyTLS${NC}"
    echo -e "  ${CYAN}7) SOCKS5${NC}"
    echo -e "  ${CYAN}8) HTTP${NC}"
    echo -e "  ${CYAN}9) DNS${NC}"
    echo -e "  ${CYAN}0) Cancel${NC}"
    read -p "$(echo -e "${YELLOW}Enter your choice [0-9]: ${NC}")" type_choice
    
    local outbound_type=""
    case $type_choice in
        1) outbound_type="direct" ;;
        2) outbound_type="block" ;;
        3) outbound_type="shadowsocks" ;;
        4) outbound_type="shadowtls" ;;
        5) outbound_type="trojan" ;;
        6) outbound_type="anytls" ;;
        7) outbound_type="socks" ;;
        8) outbound_type="http" ;;
        9) outbound_type="dns" ;;
        0) echo -e "${BLUE}Operation cancelled.${NC}"; return ;;
        *) echo -e "${RED}Invalid choice.${NC}"; return ;;
    esac
    
    # Ask for outbound tag
    read -p "$(echo -e "${YELLOW}Enter a unique tag name for this outbound: ${NC}")" current_outbound_tag
    if [[ -z "$current_outbound_tag" ]]; then
        echo -e "${RED}Error: Tag cannot be empty.${NC}"
        last_added_outbound_tag=""
        return
    fi
    
    # Check if tag already exists
    if jq -e --arg tag "$current_outbound_tag" '.outbounds[] | select(.tag == $tag)' /etc/sing-box/config.json >/dev/null 2>&1; then
        echo -e "${RED}Error: An outbound with tag '$current_outbound_tag' already exists.${NC}"
        last_added_outbound_tag=""
        return
    fi
    
    # Create outbound configuration based on type
    local outbound_config=""
    case $outbound_type in
        "direct"|"block"|"dns")
            outbound_config="{\"type\": \"$outbound_type\", \"tag\": \"$current_outbound_tag\"}"
            ;;
            
        "shadowsocks")
            read -p "$(echo -e "${YELLOW}Enter server address: ${NC}")" server_address
            read -p "$(echo -e "${YELLOW}Enter server port: ${NC}")" server_port
            
            echo -e "${YELLOW}Select encryption method:${NC}"
            echo -e "  ${CYAN}1) 2022-blake3-aes-128-gcm${NC}"
            echo -e "  ${CYAN}2) 2022-blake3-aes-256-gcm (Default)${NC}"
            echo -e "  ${CYAN}3) 2022-blake3-chacha20-poly1305${NC}"
            echo -e "  ${CYAN}4) aes-128-gcm${NC}"
            echo -e "  ${CYAN}5) aes-256-gcm${NC}"
            echo -e "  ${CYAN}6) chacha20-ietf-poly1305${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-6] (Default: 2): ${NC}")" ss_method_choice
            local ss_method
            case "$ss_method_choice" in
                1) ss_method="2022-blake3-aes-128-gcm" ;;
                3) ss_method="2022-blake3-chacha20-poly1305" ;;
                4) ss_method="aes-128-gcm" ;;
                5) ss_method="aes-256-gcm" ;;
                6) ss_method="chacha20-ietf-poly1305" ;;
                *) ss_method="2022-blake3-aes-256-gcm" ;; 
            esac
            
            read -p "$(echo -e "${YELLOW}Enter password (press Enter to generate random): ${NC}")" ss_pwd
            if [[ -z "$ss_pwd" ]]; then
                case "$ss_method" in
                    "2022-blake3-aes-128-gcm") ss_pwd=$(openssl rand -base64 16) ;;
                    *) ss_pwd=$(openssl rand -base64 32) ;;
                esac
                echo -e "${GREEN}Generated password: $ss_pwd${NC}"
            fi
            
            outbound_config=$(jq -n \
                --arg type "$outbound_type" \
                --arg tag "$current_outbound_tag" \
                --arg server "$server_address" \
                --argjson port "$server_port" \
                --arg method "$ss_method" \
                --arg password "$ss_pwd" \
                '{
                    "type": $type,
                    "tag": $tag,
                    "server": $server,
                    "server_port": $port,
                    "method": $method,
                    "password": $password,
                    "udp_over_tcp": false,
                    "multiplex": {
                        "enabled": false
                    }
                }')
            ;;
            
        "shadowtls")
            read -p "$(echo -e "${YELLOW}Enter server address: ${NC}")" server_address
            read -p "$(echo -e "${YELLOW}Enter server port: ${NC}")" server_port
            read -p "$(echo -e "${YELLOW}Enter ShadowTLS password (press Enter to generate random): ${NC}")" stls_pwd
            if [[ -z "$stls_pwd" ]]; then
                stls_pwd=$(openssl rand -base64 32)
                echo -e "${GREEN}Generated ShadowTLS password: $stls_pwd${NC}"
            fi
            
            read -p "$(echo -e "${YELLOW}Enter SNI domain (e.g., weather-data.apple.com): ${NC}")" stls_sni
            [[ -z "$stls_sni" ]] && stls_sni="weather-data.apple.com"
            
            # Get Shadowsocks configuration for ShadowTLS
            echo -e "${YELLOW}Now configure the underlying Shadowsocks settings:${NC}"
            echo -e "${YELLOW}Select encryption method:${NC}"
            echo -e "  ${CYAN}1) 2022-blake3-aes-128-gcm${NC}"
            echo -e "  ${CYAN}2) 2022-blake3-aes-256-gcm (Default)${NC}"
            echo -e "  ${CYAN}3) 2022-blake3-chacha20-poly1305${NC}"
            echo -e "  ${CYAN}4) aes-128-gcm${NC}"
            echo -e "  ${CYAN}5) aes-256-gcm${NC}"
            echo -e "  ${CYAN}6) chacha20-ietf-poly1305${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-6] (Default: 2): ${NC}")" ss_method_choice
            local ss_method
            case "$ss_method_choice" in
                1) ss_method="2022-blake3-aes-128-gcm" ;;
                3) ss_method="2022-blake3-chacha20-poly1305" ;;
                4) ss_method="aes-128-gcm" ;;
                5) ss_method="aes-256-gcm" ;;
                6) ss_method="chacha20-ietf-poly1305" ;;
                *) ss_method="2022-blake3-aes-256-gcm" ;; 
            esac
            
            read -p "$(echo -e "${YELLOW}Enter Shadowsocks password (press Enter to generate random): ${NC}")" ss_pwd
            if [[ -z "$ss_pwd" ]]; then
                case "$ss_method" in
                    "2022-blake3-aes-128-gcm") ss_pwd=$(openssl rand -base64 16) ;;
                    *) ss_pwd=$(openssl rand -base64 32) ;;
                esac
                echo -e "${GREEN}Generated Shadowsocks password: $ss_pwd${NC}"
            fi
            
            outbound_config=$(jq -n \
                --arg type "$outbound_type" \
                --arg tag "$current_outbound_tag" \
                --arg server "$server_address" \
                --argjson port "$server_port" \
                --arg password "$stls_pwd" \
                --arg sni "$stls_sni" \
                --arg ss_method "$ss_method" \
                --arg ss_pwd "$ss_pwd" \
                '{
                    "type": $type,
                    "tag": $tag,
                    "server": $server,
                    "server_port": $port,
                    "version": 3,
                    "password": $password,
                    "tls": {
                        "enabled": true,
                        "server_name": $sni
                    },
                    "shadowsocks": {
                        "method": $ss_method,
                        "password": $ss_pwd
                    },
                    "multiplex": {
                        "enabled": false
                    }
                }')
            ;;
            
        "trojan")
            read -p "$(echo -e "${YELLOW}Enter server address: ${NC}")" server_address
            read -p "$(echo -e "${YELLOW}Enter server port: ${NC}")" server_port
            read -p "$(echo -e "${YELLOW}Enter password (press Enter to generate random): ${NC}")" trojan_pwd
            if [[ -z "$trojan_pwd" ]]; then
                trojan_pwd=$(openssl rand -hex 16)
                echo -e "${GREEN}Generated password: $trojan_pwd${NC}"
            fi
            
            read -p "$(echo -e "${YELLOW}Enter SNI domain: ${NC}")" trojan_sni
            
            outbound_config=$(jq -n \
                --arg type "$outbound_type" \
                --arg tag "$current_outbound_tag" \
                --arg server "$server_address" \
                --argjson port "$server_port" \
                --arg password "$trojan_pwd" \
                --arg sni "$trojan_sni" \
                '{
                    "type": $type,
                    "tag": $tag,
                    "server": $server,
                    "server_port": $port,
                    "password": $password,
                    "tls": {
                        "enabled": true,
                        "server_name": $sni,
                        "insecure": false,
                        "utls": {
                            "enabled": true,
                            "fingerprint": "chrome"
                        }
                    },
                    "multiplex": {
                        "enabled": false
                    }
                }')
            ;;
            
        "anytls")
            read -p "$(echo -e "${YELLOW}Enter server address: ${NC}")" server_address
            read -p "$(echo -e "${YELLOW}Enter server port: ${NC}")" server_port
            read -p "$(echo -e "${YELLOW}Enter password (press Enter to generate random): ${NC}")" anytls_pwd
            if [[ -z "$anytls_pwd" ]]; then
                anytls_pwd=$(openssl rand -base64 32)
                echo -e "${GREEN}Generated password: $anytls_pwd${NC}"
            fi
            
            read -p "$(echo -e "${YELLOW}Enter SNI domain: ${NC}")" anytls_sni
            
            outbound_config=$(jq -n \
                --arg type "$outbound_type" \
                --arg tag "$current_outbound_tag" \
                --arg server "$server_address" \
                --argjson port "$server_port" \
                --arg password "$anytls_pwd" \
                --arg sni "$anytls_sni" \
                '{
                    "type": $type,
                    "tag": $tag,
                    "server": $server,
                    "server_port": $port,
                    "password": $password,
                    "tls": {
                        "enabled": true,
                        "server_name": $sni,
                        "insecure": false,
                        "utls": {
                            "enabled": true,
                            "fingerprint": "chrome"
                        }
                    },
                    "multiplex": {
                        "enabled": false
                    }
                }')
            ;;
            
        "socks")
            read -p "$(echo -e "${YELLOW}Enter server address: ${NC}")" server_address
            read -p "$(echo -e "${YELLOW}Enter server port: ${NC}")" server_port
            
            echo -e "${YELLOW}Does this SOCKS server require authentication? (y/n): ${NC}"
            read -p "" needs_auth
            local username=""
            local password=""
            if [[ "$needs_auth" == "y" || "$needs_auth" == "Y" ]]; then
                read -p "$(echo -e "${YELLOW}Enter username: ${NC}")" username
                read -p "$(echo -e "${YELLOW}Enter password: ${NC}")" password
                
                outbound_config=$(jq -n \
                    --arg type "$outbound_type" \
                    --arg tag "$current_outbound_tag" \
                    --arg server "$server_address" \
                    --argjson port "$server_port" \
                    --arg username "$username" \
                    --arg password "$password" \
                    '{
                        "type": $type,
                        "tag": $tag,
                        "server": $server,
                        "server_port": $port,
                        "version": "5",
                        "username": $username,
                        "password": $password
                    }')
            else
                outbound_config=$(jq -n \
                    --arg type "$outbound_type" \
                    --arg tag "$current_outbound_tag" \
                    --arg server "$server_address" \
                    --argjson port "$server_port" \
                    '{
                        "type": $type,
                        "tag": $tag,
                        "server": $server,
                        "server_port": $port,
                        "version": "5"
                    }')
            fi
            ;;
            
        "http")
            read -p "$(echo -e "${YELLOW}Enter server address: ${NC}")" server_address
            read -p "$(echo -e "${YELLOW}Enter server port: ${NC}")" server_port
            
            echo -e "${YELLOW}Does this HTTP proxy require authentication? (y/n): ${NC}"
            read -p "" needs_auth
            local username=""
            local password=""
            if [[ "$needs_auth" == "y" || "$needs_auth" == "Y" ]]; then
                read -p "$(echo -e "${YELLOW}Enter username: ${NC}")" username
                read -p "$(echo -e "${YELLOW}Enter password: ${NC}")" password
                
                outbound_config=$(jq -n \
                    --arg type "$outbound_type" \
                    --arg tag "$current_outbound_tag" \
                    --arg server "$server_address" \
                    --argjson port "$server_port" \
                    --arg username "$username" \
                    --arg password "$password" \
                    '{
                        "type": $type,
                        "tag": $tag,
                        "server": $server,
                        "server_port": $port,
                        "username": $username,
                        "password": $password
                    }')
            else
                outbound_config=$(jq -n \
                    --arg type "$outbound_type" \
                    --arg tag "$current_outbound_tag" \
                    --arg server "$server_address" \
                    --argjson port "$server_port" \
                    '{
                        "type": $type,
                        "tag": $tag,
                        "server": $server,
                        "server_port": $port
                    }')
            fi
            ;;
            
        *)
            echo -e "${RED}Unsupported outbound type. Cancelling.${NC}"
            return
            ;;
    esac
    
    # Add the new outbound to the configuration
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_add_outbound
    jq --argjson new_outbound "$outbound_config" '.outbounds += [$new_outbound]' \
        /etc/sing-box/config.json.bak_add_outbound > /tmp/config.json.tmp
        
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Successfully added new outbound: $current_outbound_tag ($outbound_type)${NC}"
            rm /etc/sing-box/config.json.bak_add_outbound
            last_added_outbound_tag="$current_outbound_tag"
        else
            echo -e "${RED}Error: Adding outbound failed. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_add_outbound /etc/sing-box/config.json
            restart_sing_box
            last_added_outbound_tag=""
        fi
    else
        echo -e "${RED}Error: Failed to add outbound. Check JSON configuration.${NC}"
        rm -f /tmp/config.json.tmp
        last_added_outbound_tag=""
    fi
}

# Function to remove an outbound connection
remove_outbound() {
    echo -e "\n${BLUE}--- Remove Outbound Connection ---${NC}"
    
    # Get current outbounds
    local outbounds=$(jq -r '.outbounds[] | .tag + " (" + .type + ")"' /etc/sing-box/config.json 2>/dev/null)
    if [[ -z "$outbounds" ]]; then
        echo -e "${RED}Error: Failed to parse outbounds or none defined.${NC}"
        return
    fi
    
    # Count outbounds
    local outbound_count=$(echo "$outbounds" | wc -l)
    if [[ $outbound_count -le 1 ]]; then
        echo -e "${RED}Error: Cannot remove the last outbound connection. At least one outbound must exist.${NC}"
        return
    fi
    
    echo -e "${BLUE}Current Outbound Connections:${NC}"
    echo -e "$outbounds" | nl -w2 -s') '
    
    read -p "$(echo -e "${YELLOW}Enter the number of the outbound to remove (0 to cancel): ${NC}")" outbound_num
    if [[ "$outbound_num" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    if ! [[ "$outbound_num" =~ ^[0-9]+$ ]] || [[ "$outbound_num" -lt 1 || "$outbound_num" -gt $outbound_count ]]; then
        echo -e "${RED}Invalid selection.${NC}"
        return
    fi
    
    # Get the tag of the selected outbound
    local selected_tag=$(echo "$outbounds" | sed -n "${outbound_num}p" | awk '{print $1}')
    
    # Check if this outbound is referenced in routing rules
    local outbound_in_use=$(jq -r --arg tag "$selected_tag" '.route.rules[] | select(.action == "outbound" and .outbound == $tag)' /etc/sing-box/config.json 2>/dev/null)
    if [[ -n "$outbound_in_use" ]]; then
        echo -e "${RED}Error: This outbound is used in routing rules. Please remove those rules first.${NC}"
        return
    fi
    
    # Check if this is the default outbound in route.final
    local final_outbound=$(jq -r '.route.final' /etc/sing-box/config.json 2>/dev/null)
    if [[ "$final_outbound" == "$selected_tag" ]]; then
        echo -e "${RED}Error: This outbound is set as the default (final) outbound in routing. Change the default outbound first.${NC}"
        return
    fi
    
    # Confirm removal
    echo -e "${YELLOW}Are you sure you want to remove outbound '$selected_tag'? (yes/no): ${NC}"
    read -p "" confirm
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    # Remove the outbound
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_rm_outbound
    jq --arg tag "$selected_tag" '.outbounds = [.outbounds[] | select(.tag != $tag)]' \
        /etc/sing-box/config.json.bak_rm_outbound > /tmp/config.json.tmp
        
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Successfully removed outbound: $selected_tag${NC}"
            rm /etc/sing-box/config.json.bak_rm_outbound
        else
            echo -e "${RED}Error: Removing outbound failed. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_rm_outbound /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to remove outbound. Check JSON configuration.${NC}"
        rm -f /tmp/config.json.tmp
    fi
}

# Function to modify an outbound connection
modify_outbound() {
    echo -e "\n${BLUE}--- Modify Outbound Connection ---${NC}"
    echo -e "${YELLOW}This operation removes the selected outbound and guides you to recreate it.${NC}"
    
    # Get current outbounds
    local outbounds=$(jq -r '.outbounds[] | .tag + " (" + .type + ")"' /etc/sing-box/config.json 2>/dev/null)
    if [[ -z "$outbounds" ]]; then
        echo -e "${RED}Error: Failed to parse outbounds or none defined.${NC}"
        return
    fi
    
    echo -e "${BLUE}Current Outbound Connections:${NC}"
    echo -e "$outbounds" | nl -w2 -s') '
    
    read -p "$(echo -e "${YELLOW}Enter the number of the outbound to modify (0 to cancel): ${NC}")" outbound_num
    if [[ "$outbound_num" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    local outbound_count=$(echo "$outbounds" | wc -l)
    if ! [[ "$outbound_num" =~ ^[0-9]+$ ]] || [[ "$outbound_num" -lt 1 || "$outbound_num" -gt $outbound_count ]]; then
        echo -e "${RED}Invalid selection.${NC}"
        return
    fi
    
    # Get the tag and type of the selected outbound
    local selected_outbound=$(echo "$outbounds" | sed -n "${outbound_num}p")
    local original_tag=$(echo "$selected_outbound" | awk '{print $1}') # Renamed for clarity
    local selected_type=$(echo "$selected_outbound" | sed 's/.*(\(.*\))/\1/')
    
    # Get the complete configuration of the selected outbound
    local outbound_config_to_modify=$(jq -r --arg tag "$original_tag" '.outbounds[] | select(.tag == $tag)' /etc/sing-box/config.json)
    
    echo -e "${BLUE}Selected outbound: $original_tag ($selected_type)${NC}"
    echo -e "${BLUE}Current configuration:${NC}"
    echo "$outbound_config_to_modify" | jq .
    
    # Confirm modification
    echo -e "${YELLOW}Are you sure you want to modify this outbound? (yes/no): ${NC}"
    read -p "" confirm
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
        
    # Remove the outbound first
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_mod_outbound
    jq --arg tag_to_remove "$original_tag" '.outbounds = [.outbounds[] | select(.tag != $tag_to_remove)]' \
        /etc/sing-box/config.json.bak_mod_outbound > /tmp/config.json.tmp
        
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        # Backup the current state after removal, before adding new one
        cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_mod_removed_original
        
        # Guide the user to recreate the outbound
        echo -e "${BLUE}The original outbound '$original_tag' has been removed.${NC}"
        echo -e "${BLUE}Now, please provide the new configuration for this outbound:${NC}"
        last_added_outbound_tag="" # Clear before calling add_outbound
        add_outbound # This will set last_added_outbound_tag globally
        
        local new_outbound_tag="$last_added_outbound_tag"
        
        if [[ -z "$new_outbound_tag" ]]; then
            echo -e "${RED}Failed to add the new outbound configuration. Restoring state before modification attempt...${NC}"
            mv /etc/sing-box/config.json.bak_mod_outbound /etc/sing-box/config.json # Restore original state before removal
            format_config # Attempt to format and check this restored config
            restart_sing_box
            rm -f /etc/sing-box/config.json.bak_mod_removed_original
            return
        fi

        # Update routing rules to reference the new tag if it changed and is not empty
        if [[ "$original_tag" != "$new_outbound_tag" && -n "$new_outbound_tag" ]]; then
            local routing_updated=0
            echo -e "${BLUE}Updating references from old tag '$original_tag' to new tag '$new_outbound_tag' in routing rules...${NC}"
            
            # Check if original tag was used in routing rules
            if jq -e --arg old_tag_check "$original_tag" '.route.rules[] | select(.action == "outbound" and .outbound == $old_tag_check)' /etc/sing-box/config.json &>/dev/null; then
                jq --arg old_tag_jq "$original_tag" --arg new_tag_jq "$new_outbound_tag" \
                    '.route.rules = [.route.rules[] | if .action == "outbound" and .outbound == $old_tag_jq then .outbound = $new_tag_jq else . end]' \
                    /etc/sing-box/config.json > /tmp/config.json.tmp
                    
                if [[ $? -eq 0 ]]; then
                    mv /tmp/config.json.tmp /etc/sing-box/config.json
                    routing_updated=1
                else
                    echo -e "${RED}Error updating routing rules. Check configuration manually.${NC}"
                    rm -f /tmp/config.json.tmp
                fi
            fi
            
            # Check if original tag was the default (final) outbound
            if jq -e --arg old_tag_check "$original_tag" 'select(.route.final == $old_tag_check)' /etc/sing-box/config.json &>/dev/null; then
                jq --arg new_tag_jq "$new_outbound_tag" '.route.final = $new_tag_jq' /etc/sing-box/config.json > /tmp/config.json.tmp
                
                if [[ $? -eq 0 ]]; then
                    mv /tmp/config.json.tmp /etc/sing-box/config.json
                    routing_updated=1
                else
                     echo -e "${RED}Error updating default (final) outbound. Check configuration manually.${NC}"
                    rm -f /tmp/config.json.tmp
                fi
            fi
            
            if [[ $routing_updated -eq 1 ]]; then
                echo -e "${GREEN}Updated routing rules to reference the new outbound tag '$new_outbound_tag'.${NC}"
                if format_config; then # Format and check after potential rule changes
                    restart_sing_box
                else 
                    echo -e "${RED}Configuration error after updating routing rules. Please check manually!${NC}"
                fi 
            fi
        elif [[ "$original_tag" == "$new_outbound_tag" ]]; then
             echo -e "${BLUE}Outbound tag '$original_tag' remains the same. No routing rule update needed for tag change.${NC}"
        fi
        
        rm -f /etc/sing-box/config.json.bak_mod_outbound
        rm -f /etc/sing-box/config.json.bak_mod_removed_original
    else
        echo -e "${RED}Error: Failed to remove original outbound '$original_tag' during modification. No changes made.${NC}"
        rm -f /tmp/config.json.tmp # Clean up if removal failed
        # Backup .bak_mod_outbound should remain as it is the original state
    fi
}

# Function to list all routing rules
list_routing_rules() {
    echo -e "\n${BLUE}--- Listing All Routing Rules ---${NC}"
    
    # Get the rules
    local rules_json=$(jq -r '.route.rules' /etc/sing-box/config.json 2>/dev/null)
    if [[ -z "$rules_json" || "$rules_json" == "null" ]]; then
        echo -e "${YELLOW}No routing rules configured.${NC}"
        return
    fi
    
    # Count rules
    local rule_count=$(jq -r '.route.rules | length' /etc/sing-box/config.json)
    echo -e "${BLUE}Found $rule_count routing rules:${NC}\n"
    
    # List each rule with a summary
    for i in $(seq 0 $((rule_count-1))); do
        local rule=$(jq -r ".route.rules[$i]" /etc/sing-box/config.json)
        local rule_type=$(echo "$rule" | jq -r '.type // "standard"')
        local action=$(echo "$rule" | jq -r '.action // "N/A"')
        local outbound=$(echo "$rule" | jq -r '.outbound // "N/A"')
        
        echo -e "${CYAN}Rule #$((i+1)):${NC}"
        
        # Different display based on rule type
        if [[ "$rule_type" == "logical" ]]; then
            local mode=$(echo "$rule" | jq -r '.mode // "N/A"')
            local sub_rules_count=$(echo "$rule" | jq -r '.rules | length')
            echo -e "  ${BLUE}Type: ${NC}Logical ($mode)"
            echo -e "  ${BLUE}Action: ${NC}$action"
            if [[ "$action" == "outbound" ]]; then
                echo -e "  ${BLUE}Outbound: ${NC}$outbound"
            fi
            echo -e "  ${BLUE}Contains: ${NC}$sub_rules_count sub-rules"
        else
            # Standard rule
            echo -e "  ${BLUE}Type: ${NC}Standard"
            echo -e "  ${BLUE}Action: ${NC}$action"
            
            # Show specific criteria
            if echo "$rule" | jq -e '.domain != null' &>/dev/null; then
                local domains=$(echo "$rule" | jq -r '.domain | join(", ")')
                echo -e "  ${BLUE}Domains: ${NC}$domains"
            fi
            
            if echo "$rule" | jq -e '.domain_suffix != null' &>/dev/null; then
                local suffixes=$(echo "$rule" | jq -r '.domain_suffix | join(", ")')
                echo -e "  ${BLUE}Domain Suffixes: ${NC}$suffixes"
            fi
            
            if echo "$rule" | jq -e '.domain_keyword != null' &>/dev/null; then
                local keywords=$(echo "$rule" | jq -r '.domain_keyword | join(", ")')
                echo -e "  ${BLUE}Domain Keywords: ${NC}$keywords"
            fi
            
            if echo "$rule" | jq -e '.rule_set != null' &>/dev/null; then
                local rule_sets=$(echo "$rule" | jq -r '.rule_set | join(", ")')
                echo -e "  ${BLUE}Rule Sets: ${NC}$rule_sets"
            fi
            
            if echo "$rule" | jq -e '.ip_cidr != null' &>/dev/null; then
                local cidrs=$(echo "$rule" | jq -r '.ip_cidr | join(", ")')
                echo -e "  ${BLUE}IP CIDRs: ${NC}$cidrs"
            fi
            
            if [[ "$action" == "outbound" ]]; then
                echo -e "  ${BLUE}Outbound: ${NC}$outbound"
            fi
        fi
        
        echo ""
    done
}

# Function to change the default (final) outbound
change_default_outbound() {
    echo -e "\n${BLUE}--- Change Default (Final) Outbound ---${NC}"
    
    # Get current outbounds
    local outbounds=$(jq -r '.outbounds[] | .tag + " (" + .type + ")"' /etc/sing-box/config.json 2>/dev/null)
    if [[ -z "$outbounds" ]]; then
        echo -e "${RED}Error: Failed to parse outbounds or none defined.${NC}"
        return
    fi
    
    # Get current final outbound
    local current_final=$(jq -r '.route.final // "direct"' /etc/sing-box/config.json)
    echo -e "${BLUE}Current default (final) outbound: ${CYAN}$current_final${NC}"
    
    echo -e "\n${BLUE}Available Outbounds:${NC}"
    echo -e "$outbounds" | nl -w2 -s') '
    
    read -p "$(echo -e "${YELLOW}Enter the number of the outbound to set as default (0 to cancel): ${NC}")" outbound_num
    if [[ "$outbound_num" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    local outbound_count=$(echo "$outbounds" | wc -l)
    if ! [[ "$outbound_num" =~ ^[0-9]+$ ]] || [[ "$outbound_num" -lt 1 || "$outbound_num" -gt $outbound_count ]]; then
        echo -e "${RED}Invalid selection.${NC}"
        return
    fi
    
    # Get the tag of the selected outbound
    local selected_tag=$(echo "$outbounds" | sed -n "${outbound_num}p" | awk '{print $1}')
    
    # Update final outbound
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_final
    jq --arg tag "$selected_tag" '.route.final = $tag' /etc/sing-box/config.json.bak_final > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Default (final) outbound changed to: $selected_tag${NC}"
            rm /etc/sing-box/config.json.bak_final
        else
            echo -e "${RED}Error: Failed to change default outbound. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_final /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to update default outbound using jq.${NC}"
        rm -f /tmp/config.json.tmp
    fi
}

# Function to add a new routing rule
add_routing_rule() {
    echo -e "\n${BLUE}--- Add New Routing Rule ---${NC}"
    
    # Check if we have outbounds to use in rules
    local outbounds=$(jq -r '.outbounds[] | .tag' /etc/sing-box/config.json 2>/dev/null)
    if [[ -z "$outbounds" ]]; then
        echo -e "${RED}No outbounds defined. Add at least one outbound before creating routing rules.${NC}"
        return
    fi
    
    # Select rule type
    echo -e "${YELLOW}Select rule type:${NC}"
    echo -e "  ${CYAN}1) Domain Rule${NC} (Match specific domains)"
    echo -e "  ${CYAN}2) Domain Suffix Rule${NC} (Match domain endings, e.g., .com, .netflix.com)"
    echo -e "  ${CYAN}3) Domain Keyword Rule${NC} (Match domain with keywords)"
    echo -e "  ${CYAN}4) IP CIDR Rule${NC} (Match IP address ranges)"
    echo -e "  ${CYAN}5) Rule Set Rule${NC} (Use predefined rule sets)"
    echo -e "  ${CYAN}6) Logical Rule${NC} (Combine multiple conditions with AND/OR)"
    echo -e "  ${CYAN}0) Cancel${NC}"
    read -p "$(echo -e "${YELLOW}Enter your choice [0-6]: ${NC}")" rule_type_choice
    
    if [[ "$rule_type_choice" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    # Prepare rule JSON based on type
    local rule_json=""
    local tmp_file
    tmp_file=$(mktemp /tmp/sing-box-rule.XXXXXXXXXX.json) || { echo -e "${RED}Failed to create temp file. Exiting.${NC}"; exit 1; }
    
    # Ensure tmp_file is removed on exit or interrupt
    trap 'rm -f "$tmp_file"; trap - INT TERM EXIT' INT TERM EXIT

    case $rule_type_choice in
        1) # Domain Rule
            read -p "$(echo -e "${YELLOW}Enter domain(s) to match (comma-separated): ${NC}")" domains
            if [[ -z "$domains" ]]; then
                echo -e "${RED}No domains provided. Cancelling.${NC}"
                return
            fi
            # Convert comma-separated list to JSON array
            IFS=',' read -ra domain_array <<< "$domains"
            local domain_json=$(printf '"%s",' "${domain_array[@]}" | sed 's/,$//;s/^/[/;s/$/]/')
            
            # Create initial rule JSON
            echo "{\"domain\": $domain_json}" > "$tmp_file"
            ;;
            
        2) # Domain Suffix Rule
            read -p "$(echo -e "${YELLOW}Enter domain suffix(es) to match (comma-separated, e.g., .com, .netflix.com): ${NC}")" suffixes
            if [[ -z "$suffixes" ]]; then
                echo -e "${RED}No suffixes provided. Cancelling.${NC}"
                return
            fi
            # Convert comma-separated list to JSON array
            IFS=',' read -ra suffix_array <<< "$suffixes"
            local suffix_json=$(printf '"%s",' "${suffix_array[@]}" | sed 's/,$//;s/^/[/;s/$/]/')
            
            # Create initial rule JSON
            echo "{\"domain_suffix\": $suffix_json}" > "$tmp_file"
            ;;
            
        3) # Domain Keyword Rule
            read -p "$(echo -e "${YELLOW}Enter domain keyword(s) to match (comma-separated): ${NC}")" keywords
            if [[ -z "$keywords" ]]; then
                echo -e "${RED}No keywords provided. Cancelling.${NC}"
                return
            fi
            # Convert comma-separated list to JSON array
            IFS=',' read -ra keyword_array <<< "$keywords"
            local keyword_json=$(printf '"%s",' "${keyword_array[@]}" | sed 's/,$//;s/^/[/;s/$/]/')
            
            # Create initial rule JSON
            echo "{\"domain_keyword\": $keyword_json}" > "$tmp_file"
            ;;
            
        4) # IP CIDR Rule
            read -p "$(echo -e "${YELLOW}Enter IP CIDR(s) to match (comma-separated, e.g., 192.168.1.0/24, 10.0.0.0/8): ${NC}")" cidrs
            if [[ -z "$cidrs" ]]; then
                echo -e "${RED}No CIDRs provided. Cancelling.${NC}"
                return
            fi
            # Convert comma-separated list to JSON array
            IFS=',' read -ra cidr_array <<< "$cidrs"
            local cidr_json=$(printf '"%s",' "${cidr_array[@]}" | sed 's/,$//;s/^/[/;s/$/]/')
            
            # Create initial rule JSON
            echo "{\"ip_cidr\": $cidr_json}" > "$tmp_file"
            ;;
            
        5) # Rule Set Rule
            # List available rule sets
            local rule_sets=$(jq -r '.route.rule_set[] | .tag' /etc/sing-box/config.json 2>/dev/null)
            if [[ -z "$rule_sets" ]]; then
                echo -e "${RED}No rule sets defined. Add rule sets first.${NC}"
                return
            fi
            
            echo -e "${BLUE}Available Rule Sets:${NC}"
            echo "$rule_sets" | nl -w2 -s') '
            
            read -p "$(echo -e "${YELLOW}Enter rule set number(s) to use (comma-separated): ${NC}")" rule_set_nums
            if [[ -z "$rule_set_nums" ]]; then
                echo -e "${RED}No rule sets selected. Cancelling.${NC}"
                return
            fi
            
            # Convert user input to rule set tags
            local selected_rule_sets=""
            IFS=',' read -ra rule_set_array <<< "$rule_set_nums"
            for num in "${rule_set_array[@]}"; do
                if ! [[ "$num" =~ ^[0-9]+$ ]] || [[ "$num" -lt 1 ]]; then
                    echo -e "${RED}Invalid rule set number: $num. Cancelling.${NC}"
                    return
                fi
                
                local rs_tag=$(echo "$rule_sets" | sed -n "${num}p")
                if [[ -z "$rs_tag" ]]; then
                    echo -e "${RED}Rule set number $num not found. Cancelling.${NC}"
                    return
                fi
                
                selected_rule_sets+="\"$rs_tag\","
            done
            selected_rule_sets=$(echo "$selected_rule_sets" | sed 's/,$//')
            
            # Create initial rule JSON
            echo "{\"rule_set\": [$selected_rule_sets]}" > "$tmp_file"
            ;;
            
        6) # Logical Rule
            echo -e "${YELLOW}Select logical operation mode:${NC}"
            echo -e "  ${CYAN}1) AND${NC} (All conditions must match)"
            echo -e "  ${CYAN}2) OR${NC} (Any condition can match)"
            read -p "$(echo -e "${YELLOW}Enter choice [1-2]: ${NC}")" logical_mode
            
            local mode=""
            case $logical_mode in
                1) mode="and" ;;
                2) mode="or" ;;
                *) echo -e "${RED}Invalid mode. Cancelling.${NC}"; return ;;
            esac
            
            # Create empty sub-rules array
            echo "{\"type\": \"logical\", \"mode\": \"$mode\", \"rules\": []}" > "$tmp_file"
            
            # Add sub-rules
            local sub_rules=0
            while true; do
                echo -e "\n${YELLOW}Sub-rule #$((sub_rules+1)):${NC}"
                echo -e "${YELLOW}Select sub-rule type:${NC}"
                echo -e "  ${CYAN}1) Domain Match${NC}"
                echo -e "  ${CYAN}2) Domain Suffix Match${NC}"
                echo -e "  ${CYAN}3) Domain Keyword Match${NC}"
                echo -e "  ${CYAN}4) IP CIDR Match${NC}"
                echo -e "  ${CYAN}5) Finish Adding Sub-rules${NC}"
                read -p "$(echo -e "${YELLOW}Enter choice [1-5]: ${NC}")" sub_rule_type
                
                if [[ "$sub_rule_type" -eq 5 ]]; then
                    break
                fi
                
                if [[ "$sub_rules" -ge 10 ]]; then
                    echo -e "${YELLOW}Maximum number of sub-rules (10) reached. Continuing to next step.${NC}"
                    break
                fi
                
                local sub_rule_json=""
                case $sub_rule_type in
                    1) # Domain Match
                        read -p "$(echo -e "${YELLOW}Enter domain to match: ${NC}")" domain
                        [[ -z "$domain" ]] && continue
                        sub_rule_json="{\"domain\": [\"$domain\"]}"
                        ;;
                    2) # Domain Suffix Match
                        read -p "$(echo -e "${YELLOW}Enter domain suffix to match: ${NC}")" suffix
                        [[ -z "$suffix" ]] && continue
                        sub_rule_json="{\"domain_suffix\": [\"$suffix\"]}"
                        ;;
                    3) # Domain Keyword Match
                        read -p "$(echo -e "${YELLOW}Enter domain keyword to match: ${NC}")" keyword
                        [[ -z "$keyword" ]] && continue
                        sub_rule_json="{\"domain_keyword\": [\"$keyword\"]}"
                        ;;
                    4) # IP CIDR Match
                        read -p "$(echo -e "${YELLOW}Enter IP CIDR to match: ${NC}")" cidr
                        [[ -z "$cidr" ]] && continue
                        sub_rule_json="{\"ip_cidr\": [\"$cidr\"]}"
                        ;;
                    *) echo -e "${RED}Invalid choice. Skipping this sub-rule.${NC}"; continue ;;
                esac
                
                # Add the sub-rule to the logical rule
                jq --argjson subrule "$sub_rule_json" '.rules += [$subrule]' "$tmp_file" > "$tmp_file.tmp"
                if [[ $? -eq 0 ]]; then
                    mv "$tmp_file.tmp" "$tmp_file"
                    ((sub_rules++))
                    echo -e "${GREEN}Added sub-rule. Total sub-rules: $sub_rules${NC}"
                else
                    echo -e "${RED}Failed to add sub-rule. Please try again.${NC}"
                    rm -f "$tmp_file.tmp"
                fi
            done
            
            if [[ "$sub_rules" -eq 0 ]]; then
                echo -e "${RED}No sub-rules added. Cancelling logical rule creation.${NC}"
                rm -f "$tmp_file"
                return
            fi
            ;;
            
        *) echo -e "${RED}Invalid choice. Cancelling.${NC}"; return ;;
    esac
    
    # Choose an action for the rule
    echo -e "\n${YELLOW}Select action for this rule:${NC}"
    echo -e "  ${CYAN}1) Direct${NC} (Use a specific outbound connection)"
    echo -e "  ${CYAN}2) Block${NC} (Reject the connection)"
    echo -e "  ${CYAN}3) DNS${NC} (Use specific DNS server for this rule)"
    echo -e "  ${CYAN}4) Sniff${NC} (Traffic sniffing to detect protocol, useful for TLS)"
    read -p "$(echo -e "${YELLOW}Enter your choice [1-4]: ${NC}")" action_choice
    
    local action=""
    local outbound_tag=""
    
    case $action_choice in
        1) # Direct (outbound)
            action="outbound"
            echo -e "\n${BLUE}Available Outbounds:${NC}"
            echo "$outbounds" | nl -w2 -s') '
            
            read -p "$(echo -e "${YELLOW}Enter the number of the outbound to use: ${NC}")" outbound_num
            local outbound_count=$(echo "$outbounds" | wc -l)
            if ! [[ "$outbound_num" =~ ^[0-9]+$ ]] || [[ "$outbound_num" -lt 1 || "$outbound_num" -gt $outbound_count ]]; then
                echo -e "${RED}Invalid outbound selection. Cancelling.${NC}"
                rm -f "$tmp_file"
                return
            fi
            
            outbound_tag=$(echo "$outbounds" | sed -n "${outbound_num}p")
            
            # Add action and outbound to the rule
            jq --arg action "$action" --arg outbound "$outbound_tag" '. + {action: $action, outbound: $outbound}' "$tmp_file" > "$tmp_file.tmp"
            if [[ $? -eq 0 ]]; then
                mv "$tmp_file.tmp" "$tmp_file"
            else
                echo -e "${RED}Failed to add action to rule. Cancelling.${NC}"
                rm -f "$tmp_file" "$tmp_file.tmp"
                return
            fi
            ;;
            
        2) # Block
            action="block"
            # Add action to the rule
            jq --arg action "$action" '. + {action: $action}' "$tmp_file" > "$tmp_file.tmp"
            if [[ $? -eq 0 ]]; then
                mv "$tmp_file.tmp" "$tmp_file"
            else
                echo -e "${RED}Failed to add action to rule. Cancelling.${NC}"
                rm -f "$tmp_file" "$tmp_file.tmp"
                return
            fi
            ;;
            
        3) # DNS
            action="dns"
            # List available DNS servers
            local dns_servers=$(jq -r '.dns.servers[] | .tag' /etc/sing-box/config.json 2>/dev/null)
            if [[ -z "$dns_servers" ]]; then
                echo -e "${RED}No DNS servers defined in configuration. Cancelling.${NC}"
                rm -f "$tmp_file"
                return
            fi
            
            echo -e "\n${BLUE}Available DNS Servers:${NC}"
            echo "$dns_servers" | nl -w2 -s') '
            
            read -p "$(echo -e "${YELLOW}Enter the number of the DNS server to use: ${NC}")" dns_num
            local dns_count=$(echo "$dns_servers" | wc -l)
            if ! [[ "$dns_num" =~ ^[0-9]+$ ]] || [[ "$dns_num" -lt 1 || "$dns_num" -gt $dns_count ]]; then
                echo -e "${RED}Invalid DNS server selection. Cancelling.${NC}"
                rm -f "$tmp_file"
                return
            fi
            
            local dns_tag=$(echo "$dns_servers" | sed -n "${dns_num}p")
            
            # Add action and server to the rule
            jq --arg action "$action" --arg server "$dns_tag" '. + {action: $action, server: $server}' "$tmp_file" > "$tmp_file.tmp"
            if [[ $? -eq 0 ]]; then
                mv "$tmp_file.tmp" "$tmp_file"
            else
                echo -e "${RED}Failed to add action to rule. Cancelling.${NC}"
                rm -f "$tmp_file" "$tmp_file.tmp"
                return
            fi
            ;;
            
        4) # Sniff
            action="sniff"
            # Add action to the rule
            jq --arg action "$action" '. + {action: $action}' "$tmp_file" > "$tmp_file.tmp"
            if [[ $? -eq 0 ]]; then
                mv "$tmp_file.tmp" "$tmp_file"
            else
                echo -e "${RED}Failed to add action to rule. Cancelling.${NC}"
                rm -f "$tmp_file" "$tmp_file.tmp"
                return
            fi
            ;;
            
        *) echo -e "${RED}Invalid action choice. Cancelling.${NC}"; rm -f "$tmp_file"; return ;;
    esac
    
    # Add the new rule to the configuration
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_add_rule
    
    # Check if route.rules exists, create if not
    if ! jq -e '.route.rules' /etc/sing-box/config.json &>/dev/null; then
        jq '.route += {rules: []}' /etc/sing-box/config.json.bak_add_rule > /tmp/config.json.tmp
        if [[ $? -eq 0 ]]; then
            mv /tmp/config.json.tmp /etc/sing-box/config.json.bak_add_rule
        else
            echo -e "${RED}Failed to create route.rules array. Cancelling.${NC}"
            rm -f "$tmp_file" /tmp/config.json.tmp
            rm -f /etc/sing-box/config.json.bak_add_rule
            return
        fi
    fi
    
    # Add the rule to the configuration
    local rule_from_file=$(cat "$tmp_file")
    jq --argjson new_rule "$rule_from_file" '.route.rules += [$new_rule]' /etc/sing-box/config.json.bak_add_rule > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Successfully added new routing rule with action: $action${NC}"
            [[ -n "$outbound_tag" ]] && echo -e "${GREEN}Rule will route traffic to outbound: $outbound_tag${NC}"
            rm -f /etc/sing-box/config.json.bak_add_rule
        else
            echo -e "${RED}Error: Adding rule failed. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_add_rule /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to add rule to configuration using jq.${NC}"
        rm -f /tmp/config.json.tmp
    fi
    
    # Clean up at the end of the function, trap will also handle it but good for explicit cleanup
    rm -f "$tmp_file"
    trap - INT TERM EXIT # Clear the trap
}

# Function to remove a routing rule
remove_routing_rule() {
    echo -e "\n${BLUE}--- Remove Routing Rule ---${NC}"
    
    # Get the rules
    local rule_count=$(jq -r '.route.rules | length' /etc/sing-box/config.json 2>/dev/null || echo "0")
    if [[ "$rule_count" -eq 0 ]]; then
        echo -e "${YELLOW}No routing rules configured to remove.${NC}"
        return
    fi
    
    echo -e "${BLUE}Current Routing Rules:${NC}"
    
    # Show a summary of each rule
    for i in $(seq 0 $((rule_count-1))); do
        local rule=$(jq -r ".route.rules[$i]" /etc/sing-box/config.json)
        local rule_type=$(echo "$rule" | jq -r '.type // "standard"')
        local action=$(echo "$rule" | jq -r '.action // "N/A"')
        
        echo -e "${CYAN}$((i+1))) ${NC}"
        
        # Different display based on rule type
        if [[ "$rule_type" == "logical" ]]; then
            local mode=$(echo "$rule" | jq -r '.mode // "N/A"')
            echo -e "   ${BLUE}Type: ${NC}Logical ($mode), ${BLUE}Action: ${NC}$action"
            
            if [[ "$action" == "outbound" ]]; then
                local outbound=$(echo "$rule" | jq -r '.outbound // "N/A"')
                echo -e "   ${BLUE}Outbound: ${NC}$outbound"
            fi
        else
            echo -e "   ${BLUE}Type: ${NC}Standard, ${BLUE}Action: ${NC}$action"
            
            # Show rule criteria in summary
            if echo "$rule" | jq -e '.domain != null' &>/dev/null; then
                local domains=$(echo "$rule" | jq -r '.domain | join(", ")')
                echo -e "   ${BLUE}Domains: ${NC}$domains"
            elif echo "$rule" | jq -e '.domain_suffix != null' &>/dev/null; then
                local suffixes=$(echo "$rule" | jq -r '.domain_suffix | join(", ")')
                echo -e "   ${BLUE}Domain Suffixes: ${NC}$suffixes"
            elif echo "$rule" | jq -e '.domain_keyword != null' &>/dev/null; then
                local keywords=$(echo "$rule" | jq -r '.domain_keyword | join(", ")')
                echo -e "   ${BLUE}Domain Keywords: ${NC}$keywords"
            elif echo "$rule" | jq -e '.rule_set != null' &>/dev/null; then
                local rule_sets=$(echo "$rule" | jq -r '.rule_set | join(", ")')
                echo -e "   ${BLUE}Rule Sets: ${NC}$rule_sets"
            elif echo "$rule" | jq -e '.ip_cidr != null' &>/dev/null; then
                local cidrs=$(echo "$rule" | jq -r '.ip_cidr | join(", ")')
                echo -e "   ${BLUE}IP CIDRs: ${NC}$cidrs"
            fi
            
            if [[ "$action" == "outbound" ]]; then
                local outbound=$(echo "$rule" | jq -r '.outbound // "N/A"')
                echo -e "   ${BLUE}Outbound: ${NC}$outbound"
            fi
        fi
    done
    
    read -p "$(echo -e "\n${YELLOW}Enter the number of the rule to remove (0 to cancel): ${NC}")" rule_num
    if [[ "$rule_num" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    if ! [[ "$rule_num" =~ ^[0-9]+$ ]] || [[ "$rule_num" -lt 1 || "$rule_num" -gt $rule_count ]]; then
        echo -e "${RED}Invalid rule number. Cancelling.${NC}"
        return
    fi
    
    # Adjust for zero-based indexing
    local rule_index=$((rule_num - 1))
    
    # Confirm removal
    echo -e "${YELLOW}Are you sure you want to remove rule #$rule_num? (yes/no): ${NC}"
    read -p "" confirm_remove
    if [[ "$confirm_remove" != "yes" ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    # Remove the rule
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_rm_rule
    jq --argjson idx "$rule_index" 'del(.route.rules[$idx])' /etc/sing-box/config.json.bak_rm_rule > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Successfully removed routing rule #$rule_num.${NC}"
            rm -f /etc/sing-box/config.json.bak_rm_rule
        else
            echo -e "${RED}Error: Removing rule failed. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_rm_rule /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to remove rule using jq. Restoring backup...${NC}"
        rm -f /tmp/config.json.tmp
        rm -f /etc/sing-box/config.json.bak_rm_rule # Ensure backup is also removed on jq failure before this stage
    fi
}

# Function to manage rule sets
manage_rule_sets() {
    echo -e "\n${BLUE}--- Manage Rule Sets ---${NC}"
    
    while true; do
        # Count and list rule sets
        local rule_set_count=$(jq -r '.route.rule_set | length' /etc/sing-box/config.json 2>/dev/null || echo "0")
        echo -e "${BLUE}Current Rule Sets: ${CYAN}$rule_set_count rule sets configured${NC}"
        
        if [[ $rule_set_count -gt 0 ]]; then
            echo -e "\n${BLUE}Available Rule Sets:${NC}"
            jq -r '.route.rule_set[] | .tag + " (" + .type + ")"' /etc/sing-box/config.json | nl -w2 -s') '
        fi
        
        echo -e "\n${YELLOW}Select an operation:${NC}"
        echo -e "  ${CYAN}1) Add Pre-defined Rule Set${NC}"
        echo -e "  ${CYAN}2) Add Custom Rule Set${NC}"
        echo -e "  ${CYAN}3) Remove Rule Set${NC}"
        echo -e "  ${CYAN}0) Return to Previous Menu${NC}"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-3]: ${NC}")" rule_set_choice
        
        case $rule_set_choice in
            1) add_predefined_rule_set ;;
            2) add_custom_rule_set ;;
            3) remove_rule_set ;;
            0) return ;;
            *) echo -e "${RED}Invalid choice. Please try again.${NC}" ;;
        esac
        
        [[ "$rule_set_choice" != "0" ]] && read -p "$(echo -e "\n${BLUE}Press Enter to continue...${NC}")"
    done
}

# Function to add a pre-defined rule set
add_predefined_rule_set() {
    echo -e "\n${BLUE}--- Add Pre-defined Rule Set ---${NC}"
    
    echo -e "${YELLOW}Select a pre-defined rule set category:${NC}"
    echo -e "  ${CYAN}1) GeoIP (Country-based IP routing)${NC}"
    echo -e "  ${CYAN}2) GeoSite (Domain-based routing)${NC}"
    echo -e "  ${CYAN}3) Ad Blocking${NC}"
    echo -e "  ${CYAN}4) Streaming Services${NC}"
    echo -e "  ${CYAN}5) Social Media${NC}"
    echo -e "  ${CYAN}0) Cancel${NC}"
    read -p "$(echo -e "${YELLOW}Enter your choice [0-5]: ${NC}")" category_choice
    
    if [[ "$category_choice" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    local rule_sets=()
    local category_name=""
    
    case $category_choice in
        1) # GeoIP
            category_name="GeoIP"
            rule_sets=(
                "geoip-cn|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs"
                "geoip-private|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs"
                "geoip-us|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/us.srs"
                "geoip-jp|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/jp.srs"
                "geoip-telegram|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/telegram.srs"
            )
            ;;
        2) # GeoSite
            category_name="GeoSite"
            rule_sets=(
                "geosite-cn|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs"
                "geosite-google|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google.srs"
                "geosite-github|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/github.srs"
                "geosite-twitter|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/twitter.srs"
                "geosite-telegram|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/telegram.srs"
                "geosite-facebook|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/facebook.srs"
                "geosite-category-scholar|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-scholar.srs"
            )
            ;;
        3) # Ad Blocking
            category_name="Ad Blocking"
            rule_sets=(
                "geosite-category-ads-all|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads-all.srs"
                "geosite-adaway|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/adaway.srs"
                "geosite-category-ads|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads.srs"
            )
            ;;
        4) # Streaming Services
            category_name="Streaming Services"
            rule_sets=(
                "geosite-netflix|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs"
                "geosite-disney|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/disney.srs"
                "geosite-hbo|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/hbo.srs"
                "geosite-youtube|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"
                "geosite-category-media|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-media.srs"
                "geosite-spotify|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/spotify.srs"
            )
            ;;
        5) # Social Media
            category_name="Social Media"
            rule_sets=(
                "geosite-twitter|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/twitter.srs"
                "geosite-telegram|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/telegram.srs"
                "geosite-facebook|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/facebook.srs"
                "geosite-instagram|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/instagram.srs"
                "geosite-line|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/line.srs"
                "geosite-whatsapp|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/whatsapp.srs"
            )
            ;;
        *) 
            echo -e "${RED}Invalid category choice. Cancelling.${NC}"
            return
            ;;
    esac
    
    echo -e "\n${BLUE}Available $category_name Rule Sets:${NC}"
    for i in "${!rule_sets[@]}"; do
        local rule_set_entry=${rule_sets[$i]}
        local tag=$(echo "$rule_set_entry" | cut -d'|' -f1)
        echo -e "  ${CYAN}$((i+1))) $tag${NC}"
    done
    
    read -p "$(echo -e "${YELLOW}Enter the number of the rule set to add (0 to cancel): ${NC}")" rule_set_num
    if [[ "$rule_set_num" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    if ! [[ "$rule_set_num" =~ ^[0-9]+$ ]] || [[ "$rule_set_num" -lt 1 || "$rule_set_num" -gt ${#rule_sets[@]} ]]; then
        echo -e "${RED}Invalid rule set number. Cancelling.${NC}"
        return
    fi
    
    # Get rule set info
    local rule_set_entry=${rule_sets[$((rule_set_num-1))]}
    local tag=$(echo "$rule_set_entry" | cut -d'|' -f1)
    local url=$(echo "$rule_set_entry" | cut -d'|' -f2)
    
    # Check if rule set with this tag already exists
    if jq -e --arg tag "$tag" '.route.rule_set[] | select(.tag == $tag)' /etc/sing-box/config.json &>/dev/null; then
        echo -e "${YELLOW}A rule set with tag '$tag' already exists. Do you want to replace it? (yes/no): ${NC}"
        read -p "" confirm_replace
        if [[ "$confirm_replace" != "yes" ]]; then
            echo -e "${BLUE}Operation cancelled.${NC}"
            return
        fi
        
        # Remove existing rule set with same tag
        cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_replace_rs
        jq --arg tag "$tag" '.route.rule_set = [.route.rule_set[] | select(.tag != $tag)]' /etc/sing-box/config.json.bak_replace_rs > /tmp/config.json.tmp
        
        if [[ $? -eq 0 ]]; then
            mv /tmp/config.json.tmp /etc/sing-box/config.json
        else
            echo -e "${RED}Error: Failed to remove existing rule set. Cancelling.${NC}"
            rm -f /tmp/config.json.tmp /etc/sing-box/config.json.bak_replace_rs
            return
        fi
    fi
    
    # Create rule set JSON
    local rule_set_json=$(jq -n \
        --arg tag "$tag" \
        --arg url "$url" \
        '{
            "tag": $tag,
            "type": "remote",
            "format": "binary",
            "url": $url,
            "download_detour": "direct"
        }')
    
    # Add rule set to configuration
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_add_rs
    
    # Check if route.rule_set exists, create if not
    if ! jq -e '.route.rule_set' /etc/sing-box/config.json &>/dev/null; then
        jq '.route += {"rule_set": []}' /etc/sing-box/config.json.bak_add_rs > /tmp/config.json.tmp
        if [[ $? -eq 0 ]]; then
            mv /tmp/config.json.tmp /etc/sing-box/config.json.bak_add_rs
        else
            echo -e "${RED}Failed to create route.rule_set array. Cancelling.${NC}"
            rm -f /tmp/config.json.tmp /etc/sing-box/config.json.bak_add_rs
            return
        fi
    fi
    
    # Add the rule set to configuration
    jq --argjson new_rule_set "$rule_set_json" '.route.rule_set += [$new_rule_set]' /etc/sing-box/config.json.bak_add_rs > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Successfully added rule set: $tag${NC}"
            rm -f /etc/sing-box/config.json.bak_add_rs
        else
            echo -e "${RED}Error: Adding rule set failed. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_add_rs /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to add rule set to configuration using jq.${NC}"
        rm -f /tmp/config.json.tmp /etc/sing-box/config.json.bak_add_rs
    fi
}

# Function to add a custom rule set
add_custom_rule_set() {
    echo -e "\n${BLUE}--- Add Custom Rule Set ---${NC}"
    
    read -p "$(echo -e "${YELLOW}Enter a unique tag for the rule set: ${NC}")" rule_set_tag
    if [[ -z "$rule_set_tag" ]]; then
        echo -e "${RED}Error: Tag cannot be empty.${NC}"
        return
    fi
    
    # Check if rule set with this tag already exists
    if jq -e --arg tag "$rule_set_tag" '.route.rule_set[] | select(.tag == $tag)' /etc/sing-box/config.json &>/dev/null; then
        echo -e "${RED}Error: A rule set with tag '$rule_set_tag' already exists.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Select rule set type:${NC}"
    echo -e "  ${CYAN}1) Remote Rule Set (fetch from URL)${NC}"
    echo -e "  ${CYAN}2) Local Rule Set (use local file)${NC}"
    echo -e "  ${CYAN}0) Cancel${NC}"
    read -p "$(echo -e "${YELLOW}Enter your choice [0-2]: ${NC}")" type_choice
    
    local rule_set_type=""
    local rule_set_json=""
    
    case $type_choice in
        1) # Remote Rule Set
            rule_set_type="remote"
            read -p "$(echo -e "${YELLOW}Enter rule set URL: ${NC}")" rule_set_url
            if [[ -z "$rule_set_url" ]]; then
                echo -e "${RED}Error: URL cannot be empty.${NC}"
                return
            fi
            
            echo -e "${YELLOW}Select rule set format:${NC}"
            echo -e "  ${CYAN}1) Binary (compiled, .srs format)${NC}"
            echo -e "  ${CYAN}2) Text (plaintext sing-box rule set format)${NC}"
            read -p "$(echo -e "${YELLOW}Enter format choice [1-2] (Default: 1): ${NC}")" format_choice
            
            local format="binary"
            [[ "$format_choice" == "2" ]] && format="text"
            
            rule_set_json=$(jq -n \
                --arg tag "$rule_set_tag" \
                --arg type "$rule_set_type" \
                --arg format "$format" \
                --arg url "$rule_set_url" \
                '{
                    "tag": $tag,
                    "type": $type,
                    "format": $format,
                    "url": $url,
                    "download_detour": "direct"
                }')
            ;;
            
        2) # Local Rule Set
            rule_set_type="local"
            read -p "$(echo -e "${YELLOW}Enter full path to rule set file: ${NC}")" rule_set_path
            if [[ -z "$rule_set_path" ]]; then
                echo -e "${RED}Error: File path cannot be empty.${NC}"
                return
            fi
            
            echo -e "${YELLOW}Select rule set format:${NC}"
            echo -e "  ${CYAN}1) Binary (compiled, .srs format)${NC}"
            echo -e "  ${CYAN}2) Text (plaintext sing-box rule set format)${NC}"
            read -p "$(echo -e "${YELLOW}Enter format choice [1-2] (Default: 1): ${NC}")" format_choice
            
            local format="binary"
            [[ "$format_choice" == "2" ]] && format="text"
            
            rule_set_json=$(jq -n \
                --arg tag "$rule_set_tag" \
                --arg type "$rule_set_type" \
                --arg format "$format" \
                --arg path "$rule_set_path" \
                '{
                    "tag": $tag,
                    "type": $type,
                    "format": $format,
                    "path": $path
                }')
            ;;
            
        0) echo -e "${BLUE}Operation cancelled.${NC}"; return ;;
        *) echo -e "${RED}Invalid choice. Cancelling.${NC}"; return ;;
    esac
    
    # Add rule set to configuration
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_add_custom_rs
    
    # Check if route.rule_set exists, create if not
    if ! jq -e '.route.rule_set' /etc/sing-box/config.json &>/dev/null; then
        jq '.route += {"rule_set": []}' /etc/sing-box/config.json.bak_add_custom_rs > /tmp/config.json.tmp
        if [[ $? -eq 0 ]]; then
            mv /tmp/config.json.tmp /etc/sing-box/config.json.bak_add_custom_rs
        else
            echo -e "${RED}Failed to create route.rule_set array. Cancelling.${NC}"
            rm -f /tmp/config.json.tmp /etc/sing-box/config.json.bak_add_custom_rs
            return
        fi
    fi
    
    # Add the rule set to configuration
    jq --argjson new_rule_set "$rule_set_json" '.route.rule_set += [$new_rule_set]' /etc/sing-box/config.json.bak_add_custom_rs > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Successfully added custom rule set: $rule_set_tag${NC}"
            rm -f /etc/sing-box/config.json.bak_add_custom_rs
        else
            echo -e "${RED}Error: Adding custom rule set failed. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_add_custom_rs /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to add custom rule set to configuration using jq.${NC}"
        rm -f /tmp/config.json.tmp /etc/sing-box/config.json.bak_add_custom_rs
    fi
}

# Function to remove a rule set
remove_rule_set() {
    echo -e "\n${BLUE}--- Remove Rule Set ---${NC}"
    
    # Get rule sets
    local rule_sets=$(jq -r '.route.rule_set[] | .tag' /etc/sing-box/config.json 2>/dev/null)
    if [[ -z "$rule_sets" ]]; then
        echo -e "${YELLOW}No rule sets defined to remove.${NC}"
        return
    fi
    
    echo -e "${BLUE}Available Rule Sets:${NC}"
    echo "$rule_sets" | nl -w2 -s') '
    
    read -p "$(echo -e "${YELLOW}Enter the number of the rule set to remove (0 to cancel): ${NC}")" rule_set_num
    if [[ "$rule_set_num" -eq 0 ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    local rule_set_count=$(echo "$rule_sets" | wc -l)
    if ! [[ "$rule_set_num" =~ ^[0-9]+$ ]] || [[ "$rule_set_num" -lt 1 || "$rule_set_num" -gt $rule_set_count ]]; then
        echo -e "${RED}Invalid rule set number. Cancelling.${NC}"
        return
    fi
    
    # Get the tag of the selected rule set
    local selected_tag=$(echo "$rule_sets" | sed -n "${rule_set_num}p")
    
    # Check if this rule set is used in any routing rules
    local rule_set_in_use=$(jq -e --arg tag "$selected_tag" '.route.rules[] | select(.rule_set != null) | select(.rule_set[] | contains($tag))' /etc/sing-box/config.json 2>/dev/null)
    if [[ -n "$rule_set_in_use" ]]; then
        echo -e "${RED}Error: This rule set is used in routing rules. Remove those rules first.${NC}"
        return
    fi
    
    # Confirm removal
    echo -e "${YELLOW}Are you sure you want to remove rule set '$selected_tag'? (yes/no): ${NC}"
    read -p "" confirm_remove
    if [[ "$confirm_remove" != "yes" ]]; then
        echo -e "${BLUE}Operation cancelled.${NC}"
        return
    fi
    
    # Remove the rule set
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_rm_rs
    jq --arg tag "$selected_tag" '.route.rule_set = [.route.rule_set[] | select(.tag != $tag)]' /etc/sing-box/config.json.bak_rm_rs > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Successfully removed rule set: $selected_tag${NC}"
            rm -f /etc/sing-box/config.json.bak_rm_rs
        else
            echo -e "${RED}Error: Removing rule set failed. Configuration validation failed. Restoring backup...${NC}"
            mv /etc/sing-box/config.json.bak_rm_rs /etc/sing-box/config.json
            restart_sing_box
        fi
    else
        echo -e "${RED}Error: Failed to remove rule set using jq. Restoring backup...${NC}"
        rm -f /tmp/config.json.tmp
        rm -f /etc/sing-box/config.json.bak_rm_rs
    fi
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
        echo -e "${GREEN}  6) Manage Outbound Connections${NC}"
        echo -e "${GREEN}  7) Configure Routing Rules${NC}"
        echo -e "${RED}  0) Exit Script${NC}"
        echo -e "----------------------------------------"
        read -p "$(echo -e "${YELLOW}Enter your choice [0-7]: ${NC}")" choice

        case "$choice" in
            1) install_sing_box ;;
            2) uninstall_sing_box ;;
            3) manage_sing_box ;;
            4) modify_configuration ;;
            5) show_configuration ;;
            6) manage_outbounds ;;
            7) configure_routing ;;
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
