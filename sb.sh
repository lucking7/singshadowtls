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

# Function to check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Function to check system compatibility
check_system() {
    if [[ -f /etc/redhat-release ]]; then
        echo -e "${RED}This script is only compatible with Debian/Ubuntu${NC}"
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    # 检查是否需要运行 apt update
    local update_needed=0
    if ! command -v curl >/dev/null 2>&1; then
        update_needed=1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        update_needed=1
    fi

    if [[ $update_needed -eq 1 ]]; then
        echo -e "${BLUE}Updating package lists...${NC}"
        apt update || { echo -e "${RED}apt update failed${NC}"; exit 1; }
    else
        echo -e "${GREEN}Package lists are up to date.${NC}"
    fi

    # 安装缺失的依赖
    local packages=()
    if ! command -v curl >/dev/null 2>&1; then
        packages+=("curl")
    fi
    if ! command -v jq >/dev/null 2>&1; then
        packages+=("jq")
    fi

    if [[ ${#packages[@]} -gt 0 ]]; then
        echo -e "${BLUE}Installing dependencies: ${packages[*]}...${NC}"
        apt install -y "${packages[@]}" || { echo -e "${RED}Failed to install dependencies${NC}"; exit 1; }
    else
        echo -e "${GREEN}All dependencies are already installed.${NC}"
    fi
}

# Function to get IP information
get_ip_info() {
    # 获取 IP 地址
    ip=$(curl -s "https://api.ip.sb/ip" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0")
    if [[ -z "$ip" ]]; then
        echo -e "${RED}Failed to get IP address${NC}"
        return 1
    fi

    # 获取地理位置信息
    local geoip_info
    geoip_info=$(curl -s "https://api.ip.sb/geoip/$ip" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0")
    if [[ -z "$geoip_info" ]]; then
        echo -e "${RED}Failed to get location information${NC}"
        return 1
    fi

    # 使用 jq 解析 JSON 响应
    country_code=$(echo "$geoip_info" | jq -r '.country_code')
    local city=$(echo "$geoip_info" | jq -r '.city')
    local country=$(echo "$geoip_info" | jq -r '.country')
    local isp=$(echo "$geoip_info" | jq -r '.isp')

    # 输出详细信息（可选）
    echo -e "${BLUE}IP Information:${NC}"
    echo -e "${CYAN}IP: ${NC}${ip}"
    echo -e "${CYAN}Location: ${NC}${city}, ${country} (${country_code})"
    echo -e "${CYAN}ISP: ${NC}${isp}"
}

# Function to output node information
output_node_info() {
    local port=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .listen_port' /etc/sing-box/config.json)
    local ss_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .listen_port' /etc/sing-box/config.json)
    local ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json)
    local ss_pwd=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .password' /etc/sing-box/config.json)
    local shadowtls_pwd=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .users[0].password' /etc/sing-box/config.json)
    local sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)
    local ip=$(curl -s4 ip.sb)

    echo -e "${YELLOW}Node Information:${NC}"
    echo -e "${CYAN}${country_code}${NC} = ${PINK}ss, ${ip}, ${port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true, udp-port=${ss_port}${NC}"
}

# 添加一个新的格式化配置文件的函数
format_config() {
    local temp_file="/tmp/config.json"
    if sing-box format -c /etc/sing-box/config.json > "$temp_file"; then
        if sing-box check -c "$temp_file"; then
            mv "$temp_file" /etc/sing-box/config.json
            echo -e "${GREEN}Configuration formatted and validated successfully${NC}"
            return 0
        else
            echo -e "${RED}Configuration validation failed${NC}"
            rm -f "$temp_file"
            return 1
        fi
    else
        echo -e "${RED}Configuration formatting failed${NC}"
        rm -f "$temp_file"
        return 1
    fi
}

# Function to detect architecture
get_arch() {
    case "$(uname -m)" in
        x86_64 | amd64)           echo 'amd64' ;;
        x86 | i686 | i386)        echo '386' ;;
        armv8* | arm64 | aarch64) echo 'arm64' ;;
        armv7l)                   echo 'armv7' ;;
        s390x)                    echo 's390x' ;;
        *)                        echo -e "${RED}Unsupported CPU architecture${NC}" && exit 1 ;;
    esac
}

# Function to install Sing-Box
install_sing_box() {
    get_ip_info

    ARCH=$(get_arch)

    # 获取最新beta版本
    VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases | jq -r '.[] | select(.tag_name | contains("beta")) | .tag_name' | head -n1 | sed 's/v//')

    echo -e "${BLUE}Downloading and installing Sing-Box beta ${VERSION}...${NC}"
    curl -Lo sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box_${VERSION}_linux_${ARCH}.deb"
    dpkg -i sing-box.deb
    rm sing-box.deb

    echo -e "${BLUE}Configuring Sing-Box...${NC}"
    rm -f /etc/sing-box/config.json

    echo -e "${YELLOW}Select Shadowsocks encryption method (Default: 2022-blake3-aes-256-gcm):${NC}"
    echo -e "${CYAN}1) 2022-blake3-aes-128-gcm${NC}"
    echo -e "${CYAN}2) 2022-blake3-aes-256-gcm ${NC}"
    echo -e "${CYAN}3) 2022-blake3-chacha20-poly1305${NC}"
    echo -e "${CYAN}4) aes-128-gcm${NC}"
    echo -e "${CYAN}5) aes-256-gcm${NC}"
    echo -e "${CYAN}6) chacha20-ietf-poly1305${NC}"
    read -p "Enter your choice [1-6]: " ss_method_choice
    case "$ss_method_choice" in
        1) ss_method="2022-blake3-aes-128-gcm" ;;
        3) ss_method="2022-blake3-chacha20-poly1305" ;;
        4) ss_method="aes-128-gcm" ;;
        5) ss_method="aes-256-gcm" ;;
        6) ss_method="chacha20-ietf-poly1305" ;;
        *) ss_method="2022-blake3-aes-256-gcm" ;;
    esac

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

    shadowtls_pwd=$(openssl rand -base64 32)

    read -p "Set Sing-box port [10000-65535] (Enter for random): " port
    [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1)
    until [[ -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED}Port $port is already in use, please choose another port${NC}"
        read -p "Set Sing-box port [10000-65535] (Enter for random): " port
        [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1)
    done
    echo -e "${GREEN}Using port $port for ShadowTLS${NC}"

    ss_port=$(shuf -i 10000-65535 -n 1)
    until [[ $ss_port != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port") ]]; do
        ss_port=$(shuf -i 10000-65535 -n 1)
    done
    echo -e "${GREEN}Using port $ss_port for Shadowsocks${NC}"

    read -p "Set fake website for Sing-box (without https://) [Enter for weather-data.apple.com]: " proxysite
    [[ -z $proxysite ]] && proxysite="weather-data.apple.com"
    echo -e "${GREEN}Using $proxysite as the fake website for Sing-box${NC}"

    # 添加默认策略选择
    echo -e "${YELLOW}Select default IPv4/IPv6 strategy:${NC}"
    echo -e "${CYAN}1) Prefer IPv4${NC}"
    echo -e "${CYAN}2) Prefer IPv6${NC}"
    echo -e "${CYAN}3) IPv4 only${NC}"
    echo -e "${CYAN}4) IPv6 only${NC}"
    read -p "Enter your choice [1-4]: " strategy_choice
    case "$strategy_choice" in
        1) default_strategy="prefer_ipv4" ;;
        2) default_strategy="prefer_ipv6" ;;
        3) default_strategy="ipv4_only" ;;
        4) default_strategy="ipv6_only" ;;
        *) default_strategy="prefer_ipv4" ;;
    esac

    echo -e "${BLUE}Generating configuration file...${NC}"
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
                "address": "https://1.1.1.1/dns-query",
                "address_resolver": "dns_resolver",
                "strategy": "$default_strategy"
            },
            {
                "tag": "dns_google",
                "address": "https://dns.google/dns-query",
                "address_resolver": "dns_resolver",
                "strategy": "$default_strategy"
            },
            {
                "tag": "dns_cn",
                "address": "https://dns.pub/dns-query",
                "address_resolver": "dns_resolver",
                "strategy": "ipv4_only"
            },
            {
                "tag": "dns_resolver",
                "address": "1.1.1.1",
                "detour": "direct"
            }
        ],
        "rules": [
            {
                "protocol": "dns",
                "action": "route",
                "server": "dns_cf"
            },
            {
                "rule_set": ["geosite-cn"],
                "server": "dns_cn"
            }
        ],
        "strategy": "$default_strategy",
        "independent_cache": true
    },
    "inbounds": [
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
            "tls": {
                "enabled": true,
                "server_name": "$proxysite"
            },
            "
            ": "shadowsocks-in"
        },
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": $ss_port,
            "method": "$ss_method",
            "password": "$ss_pwd",
            "network": "tcp,udp"
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "direct",
            "tag": "direct_prefer_ipv4",
            "domain_strategy": "prefer_ipv4"
        },
        {
            "type": "direct",
            "tag": "direct_ipv4_only",
            "domain_strategy": "ipv4_only"
        },
        {
            "type": "direct",
            "tag": "direct_prefer_ipv6",
            "domain_strategy": "prefer_ipv6"
        },
        {
            "type": "direct",
            "tag": "direct_ipv6_only",
            "domain_strategy": "ipv6_only"
        }
    ],
    "route": {
        "rules": [
            {
                "protocol": "dns",
                "action": "route",
                "server": "dns_cf"
            },
            {
                "rule_set": ["geosite-category-ads-all"],
                "action": "reject"
            },
            {
                "rule_set": ["geosite-ai-chat-!cn"],
                "action": "route",
                "outbound": "direct_prefer_ipv4"
            },
            {
                "rule_set": ["geosite-google"],
                "action": "route",
                "outbound": "direct_prefer_ipv4"
            },
            {
                "rule_set": ["geosite-netflix"],
                "action": "route",
                "outbound": "direct_prefer_ipv6"
            },
            {
                "rule_set": ["geosite-disney"],
                "action": "route",
                "outbound": "direct_prefer_ipv6"
            },
            {
                "rule_set": ["geosite-category-media"],
                "action": "route",
                "outbound": "direct_prefer_ipv6"
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
            }
        ],
        "auto_detect_interface": true,
        "final": "direct"
    },
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "/etc/sing-box/cache.db",
            "store_rdrc": true,
            "store_fakeip": true
        }
    }
}
EOF

    # 格式化新生成的配置文件
    if ! format_config; then
        echo -e "${RED}Failed to format configuration file${NC}"
        exit 1
    fi

    echo -e "${BLUE}Starting Sing-Box service...${NC}"
    systemctl daemon-reload
    systemctl start sing-box
    systemctl enable sing-box

    if [[ -n $(systemctl status sing-box 2>/dev/null | grep -w active) && -f '/etc/sing-box/config.json' ]]; then
        echo -e "${GREEN}Sing-Box service started successfully${NC}"
    else
        echo -e "${RED}Sing-Box service failed to start. Please check the status with 'systemctl status sing-box'${NC}"
        exit 1
    fi

    output_node_info
}

# Function to uninstall Sing-Box
uninstall_sing_box() {
    echo -e "${YELLOW}Uninstalling Sing-Box...${NC}"
    systemctl stop sing-box
    systemctl disable sing-box
    apt autoremove sing-box -y
    rm -rf /root/sing-box /etc/sing-box
    echo -e "${GREEN}Sing-Box has been completely uninstalled${NC}"
}

# Function to start Sing-Box
start_sing_box() {
    systemctl start sing-box
    systemctl enable sing-box >/dev/null 2>&1
    echo -e "${GREEN}Sing-Box started${NC}"
}

# Function to stop Sing-Box
stop_sing_box() {
    systemctl stop sing-box
    systemctl disable sing-box >/dev/null 2>&1
    echo -e "${YELLOW}Sing-Box stopped${NC}"
}

# Function to restart Sing-Box
restart_sing_box() {
    stop_sing_box
    start_sing_box
    echo -e "${GREEN}Sing-Box restarted${NC}"
}

# Function to manage Sing-Box
manage_sing_box() {
    while true; do
        echo -e "${YELLOW}Select an operation:${NC}"
        echo -e "${CYAN}1) Start${NC}"
        echo -e "${CYAN}2) Stop${NC}"
        echo -e "${CYAN}3) Restart${NC}"
        echo -e "${CYAN}0) Return to main menu${NC}"
        read -p "Enter your choice [0-3]: " switchInput
        case $switchInput in
            1 ) start_sing_box ;;
            2 ) stop_sing_box ;;
            3 ) restart_sing_box ;;
            0 ) return ;;
            * ) echo -e "${RED}Invalid choice${NC}" ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Function to change port
change_port() {
    oldport=$(grep '"listen_port"' /etc/sing-box/config.json | awk '{print $2}' | tr -d ',')
    
    read -p "Set new Sing-box port [1-65535] (Enter for random): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED}Port $port is already in use, please choose another port${NC}"
        read -p "Set new Sing-box port [1-65535] (Enter for random): " port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    done
    echo -e "${GREEN}Using new port $port for Sing-box${NC}"

    sed -i "s/\"listen_port\": $oldport/\"listen_port\": $port/" /etc/sing-box/config.json
    format_config
    restart_sing_box

    echo -e "${GREEN}Sing-box port has been changed to: $port${NC}"
    echo -e "${YELLOW}Please update your client configuration file${NC}"
    output_node_info
}

# Function to change passwords
change_passwords() {
    local old_shadowtls_pwd=$(grep -A5 '"type": "shadowtls"' /etc/sing-box/config.json | grep '"password"' | awk -F'"' '{print $4}')
    local old_ss_pwd=$(grep -A5 '"type": "shadowsocks"' /etc/sing-box/config.json | grep '"password"' | awk -F'"' '{print $4}')
    local new_shadowtls_pwd=$(openssl rand -base64 32)
    local new_ss_pwd=$(openssl rand -base64 32)

    sed -i "s/\"password\": \"$old_shadowtls_pwd\"/\"password\": \"$new_shadowtls_pwd\"/" /etc/sing-box/config.json
    sed -i "s/\"password\": \"$old_ss_pwd\"/\"password\": \"$new_ss_pwd\"/" /etc/sing-box/config.json
    format_config
    restart_sing_box

    echo -e "${GREEN}Sing-box passwords have been reset${NC}"
    echo -e "${YELLOW}Please update your client configuration file${NC}"
    output_node_info
}

# Function to change Shadowsocks encryption method
change_ss_method() {
    local old_method=$(grep -A5 '"type": "shadowsocks"' /etc/sing-box/config.json | grep '"method"' | awk -F'"' '{print $4}')
    
    echo -e "${YELLOW}Select new Shadowsocks encryption method:${NC}"
    echo -e "${CYAN}1) 2022-blake3-aes-128-gcm${NC}"
    echo -e "${CYAN}2) 2022-blake3-aes-256-gcm${NC}"
    echo -e "${CYAN}3) 2022-blake3-chacha20-poly1305${NC}"
    echo -e "${CYAN}4) aes-128-gcm${NC}"
    echo -e "${CYAN}5) aes-256-gcm${NC}"
    echo -e "${CYAN}6) chacha20-ietf-poly1305${NC}"
    read -p "Enter your choice [1-6]: " ss_method_choice
    case "$ss_method_choice" in
        1) new_method="2022-blake3-aes-128-gcm" ;;
        2) new_method="2022-blake3-aes-256-gcm" ;;
        3) new_method="2022-blake3-chacha20-poly1305" ;;
        4) new_method="aes-128-gcm" ;;
        5) new_method="aes-256-gcm" ;;
        6) new_method="chacha20-ietf-poly1305" ;;
        *) echo -e "${RED}Invalid choice${NC}" && return ;;
    esac

    sed -i "s/\"method\": \"$old_method\"/\"method\": \"$new_method\"/" /etc/sing-box/config.json
    format_config
    restart_sing_box

    echo -e "${GREEN}Shadowsocks encryption method changed to: $new_method${NC}"
    echo -e "${YELLOW}Please update your client configuration file${NC}"
    output_node_info
}

# Function to change routing preferences
change_routing_preferences() {
    local services=("AI" "Google" "Netflix" "Disney" "Media" "All")
    local strategies=("prefer_ipv4" "prefer_ipv6" "ipv4_only" "ipv6_only")
    local outbound_map=(
        "direct_prefer_ipv4"
        "direct_prefer_ipv6"
        "direct_ipv4_only"
        "direct_ipv6_only"
    )

    while true; do
        echo -e "${YELLOW}Select a service to modify its network strategy:${NC}"
        for i in "${!services[@]}"; do
            echo -e "${CYAN}$((i+1))) ${services[$i]}${NC}"
        done
        echo -e "${CYAN}0) Return to previous menu${NC}"
        read -p "Enter your choice [0-${#services[@]}]: " service_choice

        if [[ $service_choice -eq 0 ]]; then
            return
        elif [[ $service_choice -ge 1 && $service_choice -le ${#services[@]} ]]; then
            local selected_service=${services[$((service_choice-1))]}
            local rule_set="geosite-"
            
            case "$selected_service" in
                "AI") rule_set+="ai" ;;
                "Google") rule_set+="google" ;;
                "Netflix") rule_set+="netflix" ;;
                "Disney") rule_set+="disney" ;;
                "Media") rule_set+="category-media" ;;
                "All") rule_set="all" ;;
            esac

            echo -e "${YELLOW}Select network strategy for $selected_service:${NC}"
            for i in "${!strategies[@]}"; do
                echo -e "${CYAN}$((i+1))) ${strategies[$i]}${NC}"
            done
            read -p "Enter your choice [1-${#strategies[@]}]: " strategy_choice

            if [[ $strategy_choice -ge 1 && $strategy_choice -le ${#strategies[@]} ]]; then
                local selected_outbound=${outbound_map[$((strategy_choice-1))]}
                
                # 备份配置
                cp /etc/sing-box/config.json /etc/sing-box/config.json.bak

                # 使用 jq 更新规则的 outbound
                if [[ "$selected_service" == "All" ]]; then
                    jq --arg out "$selected_outbound" '
                    .route.rules = [
                        .route.rules[] | 
                        if (.rule_set != null) then
                            . + {outbound: $out}
                        else
                            .
                        end
                    ]' /etc/sing-box/config.json > /tmp/config.json
                else
                    jq --arg rs "$rule_set" --arg out "$selected_outbound" '
                    .route.rules = [
                        .route.rules[] | 
                        if (.rule_set != null and .rule_set[0] == $rs) then
                            . + {outbound: $out}
                        else
                            .
                        end
                    ]' /etc/sing-box/config.json > /tmp/config.json
                fi

                if format_config; then
                    echo -e "${GREEN}Successfully updated network strategy for $selected_service to ${strategies[$((strategy_choice-1))]}${NC}"
                    systemctl restart sing-box
                    
                    # 显示当前配置
                    echo -e "\n${YELLOW}Current configuration for $selected_service:${NC}"
                    if [[ "$selected_service" == "All" ]]; then
                        jq '.route.rules[] | select(.rule_set != null)' /etc/sing-box/config.json
                    else
                        jq --arg rs "$rule_set" '.route.rules[] | select(.rule_set != null and .rule_set[0] == $rs)' /etc/sing-box/config.json
                    fi
                else
                    echo -e "${RED}Failed to update configuration. Restoring backup.${NC}"
                    mv /etc/sing-box/config.json.bak /etc/sing-box/config.json
                fi
            fi
        fi

        echo ""
        read -p "Press Enter to continue..."
    done
}

# Function to modify configuration
modify_configuration() {
    while true; do
        echo -e "${GREEN}Select Sing-box configuration to change:${NC}"
        echo -e "${CYAN}1) Change port${NC}"
        echo -e "${CYAN}2) Reset passwords${NC}"
        echo -e "${CYAN}3) Change Shadowsocks encryption method${NC}"
        echo -e "${CYAN}4) Change routing preferences${NC}"
        echo -e "${CYAN}0) Return to main menu${NC}"
        read -p "Enter your choice [0-4]: " confAnswer
        case $confAnswer in
            1 ) change_port ;;
            2 ) change_passwords ;;
            3 ) change_ss_method ;;
            4 ) change_routing_preferences ;;
            0 ) return ;;
            * ) echo -e "${RED}Invalid choice${NC}" ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Function to show configuration
show_configuration() {
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
        echo -e "${CYAN}\"Itadori, you can do it!\" - Jujutsu Kaisen${NC}"
        echo -e "----------------------------------------"
        echo -e "${GREEN}1) Install${NC}"
        echo -e "${GREEN}2) Uninstall${NC}"
        echo -e "${GREEN}3) Manage${NC}"
        echo -e "${GREEN}4) Modify${NC}"
        echo -e "${GREEN}5) Display${NC}"
        echo -e "${GREEN}0) Exit${NC}"
        echo ""
        read -p "Enter your choice [0-5]: " choice

        case "$choice" in
            1) install_sing_box ;;
            2) uninstall_sing_box ;;
            3) manage_sing_box ;;
            4) modify_configuration ;;
            5) show_configuration ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option. Try again.${NC}" ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# Main script execution
check_root
check_system
install_dependencies

menu
