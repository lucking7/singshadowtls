#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
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
    ip=$(curl -s https://api.ipify.org)
    country_code=$(curl -s https://ipapi.co/$ip/country_code)
}

# Function to output node information
output_node_info() {
    local ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json)
    local ss_pwd=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .password' /etc/sing-box/config.json)
    local shadowtls_pwd=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .users[0].password' /etc/sing-box/config.json)
    local sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)
    local port=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .listen_port' /etc/sing-box/config.json)

    systemctl restart sing-box
    echo -e "${YELLOW}Node Information:${NC}"
    echo -e "${CYAN}${country_code} = ss, ${ip}, ${port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
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

    VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d ":" -f2 | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')

    echo -e "${BLUE}Downloading and installing Sing-Box...${NC}"
    curl -Lo sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box_${VERSION}_linux_${ARCH}.deb"
    dpkg -i sing-box.deb
    rm sing-box.deb

    echo -e "${BLUE}Configuring Sing-Box...${NC}"
    rm -f /etc/sing-box/config.json

    echo -e "${YELLOW}Select Shadowsocks encryption method:${NC}"
    echo -e "${CYAN}1) 2022-blake3-aes-128-gcm${NC}"
    echo -e "${CYAN}2) 2022-blake3-aes-256-gcm (Default)${NC}"
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
                "address": "tls://1.1.1.1",
                "address_resolver": "dns_resolver",
                "strategy": "prefer_ipv4",
                "detour": "direct"
            },
            {
                "tag": "dns_cn",
                "address": "tls://dot.pub",
                "address_resolver": "dns_resolver",
                "strategy": "ipv4_only",
                "detour": "direct"
            },
            {
                "tag": "dns_resolver",
                "address": "1.1.1.1",
                "detour": "direct"
            },
            {
                "tag": "dns_block",
                "address": "rcode://success"
            },
            {
                "tag": "dns_refused",
                "address": "rcode://refused"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "dns_resolver"
            },
            {
                "rule_set": ["geosite-category-ads-all"],
                "server": "dns_block",
                "disable_cache": true
            },
            {
                "rule_set": ["geosite-cn"],
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "dns_cn"
            },
            {
                "query_type": [
                    "A",
                    "AAAA",
                    "CNAME"
                ],
                "invert": true,
                "server": "dns_refused",
                "disable_cache": true
            }
        ],
        "final": "dns_cf",
        "independent_cache": true,
        "strategy": "prefer_ipv4"
    },
    "inbounds": [
        {
            "type": "shadowtls",
            "listen": "::",
            "listen_port": $port,
            "version": 3,
            "users": [
                {
                    "name": "singbox_user",
                    "password": "$shadowtls_pwd"
                }
            ],
            "handshake": {
                "server": "$proxysite",
                "server_port": 443
            },
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
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        },
        {
            "type": "dns",
            "tag": "dns-out"
        }
    ],
    "route": {
        "rules": [
            {
                "protocol": "dns",
                "outbound": "dns-out"
            },
            {
                "port": 853,
                "network": "tcp",
                "outbound": "block"
            },
            {
                "port": 443,
                "network": "udp",
                "outbound": "block"
            },
            {
                "ip_is_private": true,
                "outbound": "block"
            },
            {
                "rule_set": ["geoip-cn"],
                "outbound": "direct"
            },
            {
                "rule_set": ["geosite-cn"],
                "outbound": "direct"
            },
            {
                "rule_set": ["geosite-category-ads-all"],
                "outbound": "block"
            },
            {
                "rule_set": ["geosite-ai"],
                "action": "resolve",
                "strategy": "prefer_ipv4",
                "outbound": "direct"
            },
            {
                "rule_set": ["geosite-google"],
                "action": "resolve",
                "strategy": "prefer_ipv6",
                "outbound": "direct"
            },
            {
                "rule_set": ["geosite-netflix"],
                "action": "resolve",
                "strategy": "ipv6_only",
                "outbound": "direct"
            },
            {
                "rule_set": ["geosite-disney"],
                "action": "resolve",
                "strategy": "ipv6_only",
                "outbound": "direct"
            },
            {
                "rule_set": ["geosite-category-media"],
                "action": "resolve",
                "strategy": "prefer_ipv6",
                "outbound": "direct"
            }
        ],
        "rule_set": [
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-category-ads-all",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-ai",
                "type": "remote",
                "format": "binary",
                "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geoip/ai.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-google",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-disney",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-disney.srs",
                "download_detour": "direct"
            },
            {
                "tag": "geosite-category-media",
                "type": "remote",
                "format": "binary",
                "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/category-media.srs",
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
            "store_rdrc": true
        }
    }
}
EOF

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

    restart_sing_box

    echo -e "${GREEN}Shadowsocks encryption method changed to: $new_method${NC}"
    echo -e "${YELLOW}Please update your client configuration file${NC}"
    output_node_info
}

# Function to change routing preferences
change_routing_preferences() {
    local services=("Google" "Netflix" "Disney" "Media" "AI" "General")
    local strategies=("prefer_ipv4" "prefer_ipv6" "ipv4_only" "ipv6_only")

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

            echo -e "${YELLOW}Select network strategy for $selected_service:${NC}"
            for i in "${!strategies[@]}"; do
                echo -e "${CYAN}$((i+1))) ${strategies[$i]}${NC}"
            done
            read -p "Enter your choice [1-${#strategies[@]}]: " strategy_choice

            if [[ $strategy_choice -ge 1 && $strategy_choice -le ${#strategies[@]} ]]; then
                local selected_strategy=${strategies[$((strategy_choice-1))]}
                update_rule_strategy "$selected_service" "$selected_strategy"
            fi
        fi
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
        echo -e "${GREEN}3) Start/Stop/Restart${NC}"
        echo -e "${GREEN}4) Modify Configuration${NC}"
        echo -e "${GREEN}5) Show Current Configuration${NC}"
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
