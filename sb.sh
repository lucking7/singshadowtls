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

    # Check if ShadowTLS is configured
    local shadowtls_inbound_exists
    shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)

    local primary_ss_port # This will be the public port for SS if no STLS, or internal SS port if STLS exists
    primary_ss_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .listen_port' /etc/sing-box/config.json)
    local ss_method
    ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json)
    local ss_pwd
    ss_pwd=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .password' /etc/sing-box/config.json)

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

        # Output for ShadowTLS + Shadowsocks
        echo -e "${CYAN}${country_code} [ss2022][shadow-tls-v3]${NC} = ${PINK}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true, udp-port=${primary_ss_port}${NC}"
        
        # Output for direct Shadowsocks (pointing to the internal SS port)
        echo -e "\n${YELLOW}--- Optional: Direct Shadowsocks Node (Surge Format, internal port) ---${NC}"
        echo -e "${CYAN}${country_code} [ss2022]${NC} = ${PINK}ss, ${primary_ip}, ${primary_ss_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
        echo -e "\n${YELLOW}Note: The 'udp-port' for the ShadowTLS node points to the direct Shadowsocks UDP port (${primary_ss_port}).${NC}"
    else # Only Shadowsocks is configured
        echo -e "${CYAN}${country_code} [ss2022]${NC} = ${PINK}ss, ${primary_ip}, ${primary_ss_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
        echo -e "\n${YELLOW}Note: Shadowsocks is configured to listen directly on port ${primary_ss_port}.${NC}"
    fi
    echo -e "\n${YELLOW}Ensure your client supports the specified parameters and adapt if necessary.${NC}"
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

    local install_shadowtls_choice
    read -p "$(echo -e "${YELLOW}Do you want to install ShadowTLS v3 for obfuscation? (yes/no) [Default: yes]: ${NC}")" install_shadowtls_choice
    install_shadowtls_choice=$(echo "$install_shadowtls_choice" | tr '[:upper:]' '[:lower:]')
    local use_shadowtls=1 # 1 for yes, 0 for no
    if [[ "$install_shadowtls_choice" == "no" || "$install_shadowtls_choice" == "n" ]]; then
        use_shadowtls=0
        echo -e "${BLUE}ShadowTLS will not be installed. Shadowsocks will be configured to listen on a public port.${NC}"
    else
        echo -e "${GREEN}ShadowTLS will be installed (Recommended).${NC}"
    fi

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
    if [[ $use_shadowtls -eq 1 ]]; then
        shadowtls_pwd=$(openssl rand -base64 32)
        echo -e "${GREEN}Generated ShadowTLS password.${NC}"
    fi

    echo -e "\n${BLUE}--- Port Configuration ---${NC}"
    local port="" # This will be ShadowTLS port if use_shadowtls=1, or Shadowsocks public port if use_shadowtls=0
    local port_prompt_text=""

    if [[ $use_shadowtls -eq 1 ]]; then
        port_prompt_text="Set ShadowTLS listening port"
    else
        port_prompt_text="Set Shadowsocks (public) listening port"
    fi

    read -p "$(echo -e "${YELLOW}${port_prompt_text} [10000-65535] (Enter for random): ${NC}")" port
    [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1)
    until [[ "$port" =~ ^[0-9]+$ && "$port" -ge 10000 && "$port" -le 65535 && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED}Port $port is invalid, out of range [10000-65535], or already in use.${NC}"
        read -p "$(echo -e "${YELLOW}${port_prompt_text} [10000-65535] (Enter for random): ${NC}")" port
        [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1) && echo -e "${BLUE}Random port selected: $port${NC}"
    done
    if [[ $use_shadowtls -eq 1 ]]; then
        echo -e "${GREEN}Using new port $port for ShadowTLS.${NC}"
    else
        echo -e "${GREEN}Using new public port $port for Shadowsocks.${NC}"
    fi
    
    local ss_port_internal="" # Internal SS port, only used if ShadowTLS is active
    if [[ $use_shadowtls -eq 1 ]]; then
        ss_port_internal=$(shuf -i 10000-65535 -n 1)
        until [[ $ss_port_internal != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port_internal") ]]; do
            ss_port_internal=$(shuf -i 10000-65535 -n 1)
        done
        echo -e "${GREEN}Using port $ss_port_internal for Shadowsocks (internal).${NC}"
    fi

    echo -e "\n${BLUE}--- ShadowTLS Handshake Settings ---${NC}"
    local proxysite=""
    local wildcard_sni=""
    if [[ $use_shadowtls -eq 1 ]]; then
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
    
    # Determine SS listen port for the config: public if no STLS, internal if STLS is used.
    local ss_listen_port_for_config=$port 
    if [[ $use_shadowtls -eq 1 ]]; then
        ss_listen_port_for_config=$ss_port_internal
    fi

    # Start building inbounds JSON
    local inbounds_json=""
    if [[ $use_shadowtls -eq 1 ]]; then
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

    inbounds_json+=$(cat << INNER_EOF
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": $ss_listen_port_for_config,
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
INNER_EOF
)

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
    
    local oldport
    local shadowtls_inbound_exists
    shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)

    local port_type_string="ShadowTLS"
    if [[ $shadowtls_inbound_exists -ne 0 ]]; then # ShadowTLS not found, so we are changing SS public port
        port_type_string="Shadowsocks (public)"
        oldport=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .listen_port' /etc/sing-box/config.json)
    else
        oldport=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .listen_port' /etc/sing-box/config.json)
    fi
    
    echo -e "${BLUE}Current ${port_type_string} port: ${CYAN}$oldport${NC}"
    
    read -p "$(echo -e "${YELLOW}Set new ${port_type_string} port [10000-65535] (Enter for random, current: $oldport): ${NC}")" port
    if [[ -z "$port" ]]; then
        port=$(shuf -i 10000-65535 -n 1)
        echo -e "${BLUE}Random port selected: $port${NC}"
    fi

    until [[ "$port" =~ ^[0-9]+$ && "$port" -ge 10000 && "$port" -le 65535 && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED}Port $port is invalid, out of range [10000-65535], or already in use.${NC}"
        read -p "$(echo -e "${YELLOW}Set new ${port_type_string} port [10000-65535] (Enter for random): ${NC}")" port
        [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1) && echo -e "${BLUE}Random port selected: $port${NC}"
    done
    echo -e "${GREEN}Using new port $port for ${port_type_string}.${NC}"

    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_port
    
    local jq_filter
    if [[ $shadowtls_inbound_exists -ne 0 ]]; then # ShadowTLS not found, update SS port
        jq_filter='(.inbounds[] | select(.type == "shadowsocks") | .listen_port) = $newport'
    else # ShadowTLS found, update STLS port
        jq_filter='(.inbounds[] | select(.type == "shadowtls") | .listen_port) = $newport'
    fi

    jq --argjson newport "$port" "$jq_filter" /etc/sing-box/config.json.bak_port > /tmp/config.json.tmp
    
    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            echo -e "${GREEN}Sing-Box ${port_type_string} port has been changed to: $port${NC}"
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

    local shadowtls_inbound_exists
    shadowtls_inbound_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    local config_backup_file="/etc/sing-box/config.json.bak_passwd"
    cp /etc/sing-box/config.json "$config_backup_file"

    local new_ss_pwd
    local current_ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' "$config_backup_file")
    case "$current_ss_method" in
        "2022-blake3-aes-128-gcm") new_ss_pwd=$(openssl rand -base64 16) ;;
        *) new_ss_pwd=$(openssl rand -base64 32) ;;
    esac
    echo -e "${GREEN}Generated new Shadowsocks password.${NC}"

    local jq_filter_ss='((.inbounds[] | select(.type == "shadowsocks")).password) = $new_ss_pwd'
    local final_jq_filter=$jq_filter_ss

    if [[ $shadowtls_inbound_exists -eq 0 ]]; then # ShadowTLS is configured
        local new_shadowtls_pwd=$(openssl rand -base64 32)
        echo -e "${GREEN}Generated new ShadowTLS password.${NC}"
        local jq_filter_stls='((.inbounds[] | select(.type == "shadowtls") | .users[0]).password) = $new_stls_pwd'
        jq --arg new_stls_pwd "$new_shadowtls_pwd" --arg new_ss_pwd "$new_ss_pwd" "$jq_filter_stls | $jq_filter_ss" "$config_backup_file" > /tmp/config.json.tmp
    else # Only Shadowsocks
        echo -e "${YELLOW}ShadowTLS not installed, only resetting Shadowsocks password.${NC}"
        jq --arg new_ss_pwd "$new_ss_pwd" "$jq_filter_ss" "$config_backup_file" > /tmp/config.json.tmp
    fi

    if [[ $? -eq 0 ]]; then
        mv /tmp/config.json.tmp /etc/sing-box/config.json
        echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
        if format_config; then
            restart_sing_box
            if [[ $shadowtls_inbound_exists -eq 0 ]]; then
                 echo -e "${GREEN}Sing-Box ShadowTLS and Shadowsocks passwords have been reset.${NC}"
            else
                 echo -e "${GREEN}Sing-Box Shadowsocks password has been reset.${NC}"
            fi
            echo -e "${YELLOW}Please update your client configuration file.${NC}"
            output_node_info
            rm "$config_backup_file"
        else
            echo -e "${RED}Error: Password update failed due to configuration error. Restoring backup...${NC}"
            mv "$config_backup_file" /etc/sing-box/config.json
            restart_sing_box 
        fi
    else
        echo -e "${RED}Error: Failed to update passwords in JSON structure using jq.${NC}"
        rm -f /tmp/config.json.tmp
        # Restore backup if jq failed before mv
        if [ -f "$config_backup_file" ]; then mv "$config_backup_file" /etc/sing-box/config.json; fi
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

# Function to change service-specific DNS strategy in dns.rules
change_service_dns_strategy() {
    echo -e "\n${BLUE}--- Change Service-Specific DNS Strategy (in dns.rules) ---${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi
    # get_ip_info # Not strictly needed here as we are not filtering options based on live IP state anymore

    local services_map=(
        "AI Chat (!CN)|geosite-ai-chat-!cn|dns_google"
        "Google|geosite-google|dns_google"
        "Netflix|geosite-netflix|dns_cf"
        "Disney|geosite-disney|dns_cf"
        "Spotify|geosite-spotify|dns_cf"
        "General Media (category)|geosite-category-media|dns_cf"
        "China (geoip-cn, geosite-cn)|geoip-cn|dns_cf" # Simplified to just geoip-cn for jq matching ease, will apply to both if structure is consistent
        # Note: The last field is the default *server* tag if we need to reconstruct a rule, or for reference.
    )
    
    # These are the strategies the user can pick from.
    local available_strategies=("prefer_ipv4" "prefer_ipv6" "ipv4_only" "ipv6_only")

    while true; do
        echo -e "\n${YELLOW}Select a service category to modify its DNS resolution strategy:${NC}"
        for i in "${!services_map[@]}"; do
            local display_name=$(echo "${services_map[$i]}" | cut -d'|' -f1)
            local rule_set_tag_jq=$(echo "${services_map[$i]}" | cut -d'|' -f2)
            # Try to find the rule by the first rule_set tag if multiple exist (e.g., geoip-cn, geosite-cn)
            local first_rs_tag=$(echo "$rule_set_tag_jq" | cut -d',' -f1)
            
            local current_strategy=$(jq -r --arg rs "$first_rs_tag" '.dns.rules[] | select(.rule_set != null and (.rule_set[0] == $rs or .rule_set == $rs)) | .strategy // "not set"' /etc/sing-box/config.json)
            local current_server=$(jq -r --arg rs "$first_rs_tag" '.dns.rules[] | select(.rule_set != null and (.rule_set[0] == $rs or .rule_set == $rs)) | .server // "not set"' /etc/sing-box/config.json)
            echo -e "  ${CYAN}$((i+1))) ${display_name}${NC} (DNS Server: ${MAGENTA}${current_server}${NC}, Strategy: ${ORANGE}${current_strategy}${NC})"
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
        local rule_set_tag_for_jq_match=$(echo "$selected_service_entry" | cut -d'|' -f2 | cut -d',' -f1) # Use first tag for matching rule
            
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
        
        cp /etc/sing-box/config.json /etc/sing-box/config.json.bak_dns_strat
        
        # jq query to update the strategy for the rule matching the first rule_set tag
        # This assumes rule_set is an array or a single string.
        local jq_query='
            .dns.rules |= map(
                if (.rule_set != null and (.rule_set[0] == $rs_tag or .rule_set == $rs_tag)) then
                    .strategy = $new_strategy 
                else
                    . 
                end
            )'
        
        jq --arg rs_tag "$rule_set_tag_for_jq_match" --arg new_strategy "$selected_strategy" "$jq_query" \
            /etc/sing-box/config.json.bak_dns_strat > /tmp/config.json.tmp

        if [[ $? -eq 0 ]]; then
            mv /tmp/config.json.tmp /etc/sing-box/config.json
            echo -e "${BLUE}Formatting and validating updated configuration...${NC}"
            if format_config; then
                echo -e "${GREEN}Successfully updated DNS strategy for '${service_display_name}' to '${selected_strategy}'.${NC}"
                systemctl restart sing-box
                echo -e "\n${YELLOW}Current DNS rule for '${service_display_name}':${NC}"
                jq --arg rs "$rule_set_tag_for_jq_match" '.dns.rules[] | select(.rule_set != null and (.rule_set[0] == $rs or .rule_set == $rs))' /etc/sing-box/config.json
                rm /etc/sing-box/config.json.bak_dns_strat
            else
                echo -e "${RED}Error: Strategy update failed due to configuration error. Restoring backup...${NC}"
                mv /etc/sing-box/config.json.bak_dns_strat /etc/sing-box/config.json
                restart_sing_box
            fi
        else
            echo -e "${RED}Error: Failed to update DNS strategy using jq. Exit status: $?${NC}"
            cat /tmp/config.json.tmp # Show what jq produced if it failed but still wrote to tmp
            rm -f /tmp/config.json.tmp
        fi
        read -p "$(echo -e "\n${BLUE}Press Enter to continue...${NC}")"
    done
}

# Function to change ShadowTLS wildcard SNI mode
change_wildcard_sni() {
    echo -e "\n${BLUE}--- Change ShadowTLS Wildcard SNI Mode ---${NC}"
    if [ ! -f /etc/sing-box/config.json ]; then echo -e "${RED}Error: /etc/sing-box/config.json not found.${NC}"; return; fi

    local current_wildcard_sni=$(jq -r '(.inbounds[] | select(.type == "shadowtls") | .wildcard_sni) // "not_applicable"' /etc/sing-box/config.json)

    if [[ "$current_wildcard_sni" == "not_applicable" ]]; then
        echo -e "${YELLOW}ShadowTLS is not installed. Wildcard SNI mode cannot be changed.${NC}"
        return
    fi

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

    local shadowtls_installed=0
    jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1 && shadowtls_installed=1

    while true; do
        echo -e "\n${GREEN}--- Modify Sing-Box Configuration ---${NC}"
        echo -e "${YELLOW}Select an option to change:${NC}"
        
        if [[ $shadowtls_installed -eq 1 ]]; then
            echo -e "  ${CYAN}1) Change ShadowTLS Port${NC}"
            echo -e "  ${CYAN}2) Reset Passwords (ShadowTLS & Shadowsocks)${NC}"
            echo -e "  ${CYAN}3) Change Shadowsocks Encryption Method${NC}"
            echo -e "  ${CYAN}4) Change Service-Specific DNS Strategy${NC}"
            echo -e "  ${CYAN}5) Change ShadowTLS Wildcard SNI Mode${NC}"
            echo -e "  ${CYAN}0) Return to Main Menu${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [0-5]: ${NC}")" confAnswer
        else
            echo -e "  ${CYAN}1) Change Shadowsocks Public Port${NC}"
            echo -e "  ${CYAN}2) Reset Shadowsocks Password${NC}"
            echo -e "  ${CYAN}3) Change Shadowsocks Encryption Method${NC}"
            echo -e "  ${CYAN}4) Change Service-Specific DNS Strategy${NC}"
            # Option 5 (Wildcard SNI) is omitted if ShadowTLS is not installed
            echo -e "  ${CYAN}0) Return to Main Menu${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [0-4]: ${NC}")" confAnswer
        fi

        case $confAnswer in
            1 ) change_port ;;
            2 ) change_passwords ;;
            3 ) change_ss_method ;;
            4 ) change_service_dns_strategy ;;
            5 ) if [[ $shadowtls_installed -eq 1 ]]; then change_wildcard_sni; else echo -e "${RED}Invalid option. ShadowTLS not installed.${NC}"; fi ;;
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
