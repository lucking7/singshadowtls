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

    # Shadowsocks密码设置
    echo -e "\n${YELLOW}Shadowsocks 密码设置：${NC}"
    echo -e "  - 输入自定义密码"
    echo -e "  - 按回车键随机生成密码"
    read -p "$(echo -e "${YELLOW}输入 Shadowsocks 密码 (回车随机生成): ${NC}")" ss_pwd
    
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
        echo -e "${GREEN}已生成 Shadowsocks 密码。${NC}"
    else
        echo -e "${GREEN}使用自定义 Shadowsocks 密码。${NC}"
    fi

    local shadowtls_pwd=""
    if [[ $use_shadowtls -eq 1 ]]; then
        echo -e "\n${YELLOW}ShadowTLS 密码设置：${NC}"
        echo -e "  - 输入自定义密码"
        echo -e "  - 按回车键随机生成密码"
        read -p "$(echo -e "${YELLOW}输入 ShadowTLS 密码 (回车随机生成): ${NC}")" shadowtls_pwd
        
        if [[ -z "$shadowtls_pwd" ]]; then
            shadowtls_pwd=$(openssl rand -base64 32)
            echo -e "${GREEN}已生成 ShadowTLS 密码。${NC}"
        else
            echo -e "${GREEN}使用自定义 ShadowTLS 密码。${NC}"
        fi
    fi

    echo -e "\n${BLUE}--- Port Configuration ---${NC}"
    local port="" # This will be ShadowTLS port if use_shadowtls=1, or Shadowsocks public port if use_shadowtls=0
    local port_prompt_text=""

    if [[ $use_shadowtls -eq 1 ]]; then
        port_prompt_text="ShadowTLS 监听端口"
    else
        port_prompt_text="Shadowsocks (公网) 监听端口"
    fi

    echo -e "${YELLOW}端口设置提示：${NC}"
    echo -e "  - 输入指定端口号 (10000-65535)"
    echo -e "  - 按回车键随机生成端口"
    read -p "$(echo -e "${YELLOW}设置 ${port_prompt_text} (回车随机生成): ${NC}")" port
    
    if [[ -z "$port" ]]; then
        port=$(shuf -i 10000-65535 -n 1)
        echo -e "${BLUE}已随机生成端口: $port${NC}"
    fi
    
    # 验证端口
    while true; do
        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}错误：端口必须是数字。${NC}"
        elif [[ "$port" -lt 10000 || "$port" -gt 65535 ]]; then
            echo -e "${RED}错误：端口必须在 10000-65535 范围内。${NC}"
        elif [[ -n $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED}错误：端口 $port 已被占用。${NC}"
        else
            break
        fi
        read -p "$(echo -e "${YELLOW}请重新输入端口 (回车随机生成): ${NC}")" port
        if [[ -z "$port" ]]; then
            port=$(shuf -i 10000-65535 -n 1)
            echo -e "${BLUE}已随机生成端口: $port${NC}"
        fi
    done
    
    if [[ $use_shadowtls -eq 1 ]]; then
        echo -e "${GREEN}将使用端口 $port 作为 ShadowTLS。${NC}"
    else
        echo -e "${GREEN}将使用端口 $port 作为 Shadowsocks 公网端口。${NC}"
    fi
    
    local ss_port_internal="" # Internal SS port, only used if ShadowTLS is active
    if [[ $use_shadowtls -eq 1 ]]; then
        ss_port_internal=$(shuf -i 10000-65535 -n 1)
        until [[ $ss_port_internal != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port_internal") ]]; do
            ss_port_internal=$(shuf -i 10000-65535 -n 1)
        done
        echo -e "${GREEN}将使用端口 $ss_port_internal 作为 Shadowsocks (内部)。${NC}"
    fi

    echo -e "\n${BLUE}--- ShadowTLS Handshake Settings ---${NC}"
    local proxysite=""
    local wildcard_sni=""
    if [[ $use_shadowtls -eq 1 ]]; then
        echo -e "${YELLOW}SNI 设置提示：${NC}"
        echo -e "  - 输入自定义域名 (例如: weather-data.apple.com)"
        echo -e "  - 按回车键使用默认值: weather-data.apple.com"
        read -p "$(echo -e "${YELLOW}设置 ShadowTLS 的 SNI (伪装网站域名) (回车使用默认): ${NC}")" proxysite
        if [[ -z $proxysite ]]; then
            proxysite="weather-data.apple.com"
        fi
        echo -e "${GREEN}使用 SNI: $proxysite${NC}"

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
    echo -e "${BLUE}--- Uninstalling Sing-Box ---${NC}"
    
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
    
    echo -e "\n${BLUE}--- Change Port Configuration ---${NC}"
    echo -e "${CYAN}Which port would you like to change?${NC}"
    echo -e "1) ShadowTLS Port"
    echo -e "2) Shadowsocks Port"
    read -p "Enter your choice (1-2): " port_choice
    
    case $port_choice in
        1)
            local tag="shadowtls"
            local service_name="ShadowTLS"
            ;;
        2)
            local tag="shadowsocks"
            local service_name="Shadowsocks"
            ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            return 1
            ;;
    esac
    
    local current_port=$(jq -r ".inbounds[] | select(.tag == \"$tag\") | .listen_port" /etc/sing-box/config.json)
    echo -e "${CYAN}Current $service_name port: $current_port${NC}"
    
    echo -e "${YELLOW}自定义端口输入提示：${NC}"
    echo -e "  - 输入指定端口号 (10000-65535)"
    echo -e "  - 按回车键随机生成端口"
    
    read -p "请输入新端口号或按回车: " new_port
    
    if [[ -z "$new_port" ]]; then
        # Generate random port
        while true; do
            new_port=$((RANDOM % 55536 + 10000))
            if ! ss -tuln | grep -q ":$new_port "; then
                echo -e "${GREEN}随机生成端口: $new_port${NC}"
                break
            fi
        done
    else
        # Validate user input
        if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 10000 ] || [ "$new_port" -gt 65535 ]; then
            echo -e "${RED}错误: 端口必须是 10000-65535 之间的数字。${NC}"
            return 1
        fi
        
        # Check if port is in use
        if ss -tuln | grep -q ":$new_port "; then
            echo -e "${RED}错误: 端口 $new_port 已被占用。${NC}"
            return 1
        fi
    fi
    
    # Update configuration
    jq ".inbounds = [.inbounds[] | if .tag == \"$tag\" then .listen_port = $new_port else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
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
        echo -e "${GREEN}Port changed successfully! New $service_name port: $new_port${NC}"
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
    
    echo -e "\n${BLUE}--- Change Passwords ---${NC}"
    
    # Get current encryption method
    local current_method=$(jq -r '.inbounds[] | select(.tag == "shadowsocks") | .method' /etc/sing-box/config.json)
    
    # Change ShadowTLS password
    echo -e "\n${CYAN}ShadowTLS 密码设置：${NC}"
    echo -e "${YELLOW}自定义密码输入提示：${NC}"
    echo -e "  - 输入自定义密码"
    echo -e "  - 按回车键随机生成密码"
    
    read -p "请输入新的 ShadowTLS 密码或按回车: " shadowtls_password
    
    if [[ -z "$shadowtls_password" ]]; then
        shadowtls_password=$(openssl rand -base64 16)
        echo -e "${GREEN}随机生成密码: $shadowtls_password${NC}"
    fi
    
    # Change Shadowsocks password
    echo -e "\n${CYAN}Shadowsocks 密码设置：${NC}"
    echo -e "${YELLOW}自定义密码输入提示：${NC}"
    echo -e "  - 输入自定义密码"
    echo -e "  - 按回车键随机生成密码"
    
    read -p "请输入新的 Shadowsocks 密码或按回车: " shadowsocks_password
    
    if [[ -z "$shadowsocks_password" ]]; then
        if [[ "$current_method" =~ ^2022 ]]; then
            shadowsocks_password=$(openssl rand -base64 32)
        else
            shadowsocks_password=$(openssl rand -base64 16)
        fi
        echo -e "${GREEN}随机生成密码: $shadowsocks_password${NC}"
    fi
    
    # Update configuration
    jq ".inbounds = [.inbounds[] | if .tag == \"shadowtls\" then .handshake.server.password = \"$shadowtls_password\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
    mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    
    jq ".inbounds = [.inbounds[] | if .tag == \"shadowsocks\" then .password = \"$shadowsocks_password\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
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
        echo -e "${GREEN}Passwords changed successfully!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Function to change ShadowTLS password only
change_shadowtls_password() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}--- Change ShadowTLS Password ---${NC}"
    
    echo -e "${YELLOW}自定义密码输入提示：${NC}"
    echo -e "  - 输入自定义密码"
    echo -e "  - 按回车键随机生成密码"
    
    read -p "请输入新的 ShadowTLS 密码或按回车: " new_password
    
    if [[ -z "$new_password" ]]; then
        new_password=$(openssl rand -base64 16)
        echo -e "${GREEN}随机生成密码: $new_password${NC}"
    fi
    
    # Update configuration
    jq ".inbounds = [.inbounds[] | if .tag == \"shadowtls\" then .handshake.server.password = \"$new_password\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
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
        echo -e "${GREEN}ShadowTLS password changed successfully!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Function to change ShadowTLS SNI
change_shadowtls_sni() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}--- Change ShadowTLS SNI ---${NC}"
    
    local current_sni=$(jq -r '.inbounds[] | select(.tag == "shadowtls") | .handshake.server.server_name' /etc/sing-box/config.json)
    echo -e "${CYAN}Current SNI: $current_sni${NC}"
    
    echo -e "\n${CYAN}Select new SNI:${NC}"
    echo -e "1) www.tesla.com (Recommended)"
    echo -e "2) www.bing.com"
    echo -e "3) www.microsoft.com"
    echo -e "4) www.apple.com"
    echo -e "5) www.amazon.com"
    echo -e "6) www.cloudflare.com"
    echo -e "7) gateway.icloud.com"
    echo -e "8) itunes.apple.com"
    echo -e "9) download.microsoft.com"
    echo -e "10) www.paypal.com"
    echo -e "11) Custom domain"
    
    read -p "Enter your choice (1-11): " sni_choice
    
    case $sni_choice in
        1) new_sni="www.tesla.com" ;;
        2) new_sni="www.bing.com" ;;
        3) new_sni="www.microsoft.com" ;;
        4) new_sni="www.apple.com" ;;
        5) new_sni="www.amazon.com" ;;
        6) new_sni="www.cloudflare.com" ;;
        7) new_sni="gateway.icloud.com" ;;
        8) new_sni="itunes.apple.com" ;;
        9) new_sni="download.microsoft.com" ;;
        10) new_sni="www.paypal.com" ;;
        11)
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
    jq ".inbounds = [.inbounds[] | if .tag == \"shadowtls\" then .handshake.server.server_name = \"$new_sni\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
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

# Function to toggle IPv6
toggle_ipv6() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}--- Toggle IPv6 ---${NC}"
    
    # Check current IPv6 status
    local current_strategy=$(jq -r '.dns.strategy' /etc/sing-box/config.json)
    local new_strategy
    
    if [[ "$current_strategy" == "ipv4_only" ]]; then
        new_strategy="prefer_ipv4"
        echo -e "${CYAN}Current status: IPv6 disabled (ipv4_only)${NC}"
        echo -e "${GREEN}Enabling IPv6 (prefer_ipv4)...${NC}"
    else
        new_strategy="ipv4_only"
        echo -e "${CYAN}Current status: IPv6 enabled ($current_strategy)${NC}"
        echo -e "${YELLOW}Disabling IPv6 (ipv4_only)...${NC}"
    fi
    
    # Update only the global DNS strategy, not individual rules
    jq ".dns.strategy = \"$new_strategy\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json
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
        if [[ "$new_strategy" == "ipv4_only" ]]; then
            echo -e "${GREEN}IPv6 has been disabled successfully!${NC}"
        else
            echo -e "${GREEN}IPv6 has been enabled successfully!${NC}"
        fi
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
    
    echo -e "\n${BLUE}--- DNS Strategy Management ---${NC}"
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
            
            jq ".dns.strategy = \"$new_strategy\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json
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
    
    echo -e "\n${BLUE}--- Change DNS Servers ---${NC}"
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
    
    echo -e "\n${BLUE}--- Current Configuration ---${NC}"
    cat /etc/sing-box/config.json | jq '.'
}

# Function to view service status
check_status() {
    echo -e "\n${BLUE}--- Sing-Box Service Status ---${NC}"
    systemctl status sing-box
}

# Function to view logs
view_logs() {
    echo -e "\n${BLUE}--- Sing-Box Logs (Last 50 lines) ---${NC}"
    journalctl -u sing-box -n 50 --no-pager
}

# Function to restart service
restart_service() {
    echo -e "\n${BLUE}--- Restarting Sing-Box Service ---${NC}"
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
    
    echo -e "\n${BLUE}--- Change Shadowsocks Encryption Method ---${NC}"
    
    local current_method=$(jq -r '.inbounds[] | select(.tag == "shadowsocks") | .method' /etc/sing-box/config.json)
    echo -e "${CYAN}Current method: $current_method${NC}"
    
    echo -e "\n${CYAN}Select new encryption method:${NC}"
    echo -e "1) 2022-blake3-aes-128-gcm (Recommended)"
    echo -e "2) 2022-blake3-aes-256-gcm"
    echo -e "3) 2022-blake3-chacha20-poly1305"
    echo -e "4) aes-128-gcm"
    echo -e "5) aes-256-gcm"
    echo -e "6) chacha20-ietf-poly1305"
    
    read -p "Enter your choice (1-6): " method_choice
    
    case $method_choice in
        1) new_method="2022-blake3-aes-128-gcm" ;;
        2) new_method="2022-blake3-aes-256-gcm" ;;
        3) new_method="2022-blake3-chacha20-poly1305" ;;
        4) new_method="aes-128-gcm" ;;
        5) new_method="aes-256-gcm" ;;
        6) new_method="chacha20-ietf-poly1305" ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            return 1
            ;;
    esac
    
    # Generate appropriate password based on method
    echo -e "\n${CYAN}Shadowsocks 密码设置：${NC}"
    echo -e "${YELLOW}自定义密码输入提示：${NC}"
    echo -e "  - 输入自定义密码"
    echo -e "  - 按回车键随机生成密码"
    
    read -p "请输入新的 Shadowsocks 密码或按回车: " new_password
    
    if [[ -z "$new_password" ]]; then
        if [[ "$new_method" =~ ^2022 ]]; then
            new_password=$(openssl rand -base64 32)
        else
            new_password=$(openssl rand -base64 16)
        fi
        echo -e "${GREEN}随机生成密码: $new_password${NC}"
    fi
    
    # Update configuration
    jq ".inbounds = [.inbounds[] | if .tag == \"shadowsocks\" then (.method = \"$new_method\" | .password = \"$new_password\") else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json
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
        echo -e "${GREEN}Encryption method changed successfully!${NC}"
        echo -e "${GREEN}New method: $new_method${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Main menu
show_menu() {
    clear
    echo -e "${BLUE}=====================================${NC}"
    echo -e "${CYAN}    Sing-Box Management Script${NC}"
    echo -e "${BLUE}=====================================${NC}"
    echo -e "${GREEN}1)${NC} Install Sing-Box"
    echo -e "${GREEN}2)${NC} Uninstall Sing-Box"
    echo -e "${GREEN}3)${NC} View Node Information"
    echo -e "${GREEN}4)${NC} View Configuration"
    echo -e "${GREEN}5)${NC} View Service Status"
    echo -e "${GREEN}6)${NC} View Logs"
    echo -e "${GREEN}7)${NC} Restart Service"
    echo -e "${GREEN}8)${NC} Change Port"
    echo -e "${GREEN}9)${NC} Change All Passwords"
    echo -e "${GREEN}10)${NC} Change ShadowTLS Password"
    echo -e "${GREEN}11)${NC} Change ShadowTLS SNI"
    echo -e "${GREEN}12)${NC} Change Shadowsocks Method"
    echo -e "${GREEN}13)${NC} Toggle IPv6"
    echo -e "${GREEN}14)${NC} Manage DNS Strategies"
    echo -e "${GREEN}15)${NC} Change DNS Servers"
    echo -e "${GREEN}0)${NC} Exit"
    echo -e "${BLUE}=====================================${NC}"
}

# Main execution
main() {
    check_root
    check_system
    
    while true; do
        show_menu
        read -p "Enter your choice: " choice
        
        case $choice in
            1)
                install_dependencies
                get_ip_info
                install_sing_box
                ;;
            2)
                uninstall_sing_box
                ;;
            3)
                output_node_info
                ;;
            4)
                view_config
                ;;
            5)
                check_status
                ;;
            6)
                view_logs
                ;;
            7)
                restart_service
                ;;
            8)
                change_port
                ;;
            9)
                change_passwords
                ;;
            10)
                change_shadowtls_password
                ;;
            11)
                change_shadowtls_sni
                ;;
            12)
                change_ss_method
                ;;
            13)
                toggle_ipv6
                ;;
            14)
                manage_dns_strategies
                ;;
            15)
                change_dns_servers
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
