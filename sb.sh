#!/bin/bash

# 错误处理
set -uo pipefail

# Colors
RED='\033[0;31m'    # Error/Warning
GREEN='\033[0;32m'  # Success
YELLOW='\033[1;33m' # Accent/CTA/Input prompts (Bold Yellow)
BLUE='\033[0;34m'   # Primary/Titles
MAGENTA='\033[0;35m' # Special Data (e.g., node password parts)
CYAN='\033[0;36m'   # Secondary/Information/Options
NC='\033[0m'      # No Color

# 版本信息
SCRIPT_VERSION="3.2"
SCRIPT_NAME="Sing-Box & ShadowTLS Multi-Deployment Script"

# 日志配置
LOG_DIR="/var/log/sing-box"
LOG_FILE="${LOG_DIR}/installer.log"
DEBUG_MODE=${DEBUG_MODE:-0}

# 配置目录
CONFIG_DIR="/etc/sing-box"
BACKUP_DIR="${CONFIG_DIR}/backups"

# Global IP variables
ipv4_address=""
ipv6_address=""
has_ipv4=0
has_ipv6=0
primary_ip=""
country_code=""

# Global TLS verification variable
VALID_TLS13_DOMAINS=""

# 初始化日志目录
init_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR"
        chmod 755 "$LOG_DIR"
    fi
    # 日志轮转（保留最近10个日志文件）
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d_%H%M%S)"
        find "$LOG_DIR" -name "installer.log.*" -type f | sort -r | tail -n +10 | xargs rm -f 2>/dev/null || true
    fi
}

# 日志记录函数
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 写入日志文件
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    
    # 控制台输出
    case "$level" in
        ERROR)   echo -e "${RED}[错误] $message${NC}" >&2 ;;
        WARN)    echo -e "${YELLOW}[警告] $message${NC}" ;;
        INFO)    echo -e "${CYAN}[信息] $message${NC}" ;;
        SUCCESS) echo -e "${GREEN}[成功] $message${NC}" ;;
        DEBUG)   [[ $DEBUG_MODE -eq 1 ]] && echo -e "${MAGENTA}[调试] $message${NC}" ;;
    esac
}

# 错误处理函数
error_handler() {
    local exit_code=$?
    local line_no=${1:-$LINENO}
    
    log ERROR "错误发生在第 $line_no 行，退出码: $exit_code"
    
    # 提示用户查看日志
    if [[ $exit_code -ne 0 ]]; then
        echo -e "${YELLOW}详细错误信息已记录到: $LOG_FILE${NC}"
        echo -e "${YELLOW}使用命令查看: tail -n 50 $LOG_FILE${NC}"
    fi
}

# 设置错误捕获
trap 'error_handler $LINENO' ERR

# 进度条显示函数
show_progress() {
    local current=$1
    local total=$2
    local message="${3:-处理中}"
    local width=50
    
    if [[ $total -eq 0 ]]; then
        return
    fi
    
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    
    printf "\r%s [" "$message"
    printf "%${filled}s" | tr ' ' '='
    printf "%$((width - filled))s" | tr ' ' '-'
    printf "] %d%%" $percentage
    
    if [[ $current -eq $total ]]; then
        echo
    fi
}

# 操作确认函数
confirm_action() {
    local message="${1:-确认执行此操作？}"
    local default="${2:-n}"
    
    if [[ "$default" == "y" ]]; then
        read -p "$(echo -e "${YELLOW}${message} [Y/n]: ${NC}")" -n 1 -r response
    else
        read -p "$(echo -e "${YELLOW}${message} [y/N]: ${NC}")" -n 1 -r response
    fi
    echo
    
    if [[ -z "$response" ]]; then
        response="$default"
    fi
    
    [[ "$response" =~ ^[Yy]$ ]]
}

# 初始化日志系统
init_logging

# Function to check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "脚本必须以 root 权限运行"
        echo -e "${RED}错误: 此脚本必须以 root 权限运行${NC}"
        exit 1
    fi
    log INFO "Root 权限检查通过"
}

# Function to check system compatibility (Debian/Ubuntu only)
check_system() {
    log INFO "检查系统兼容性..."
    if [[ -f /etc/redhat-release ]]; then
        log ERROR "不支持的系统: RedHat/CentOS"
        echo -e "${RED}错误: 此脚本仅支持 Debian/Ubuntu 系统${NC}"
        exit 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        log ERROR "systemctl 未找到"
        echo -e "${RED}错误: 未找到 systemctl，需要 systemd 系统${NC}"
        exit 1
    fi
    log SUCCESS "系统兼容性检查通过"
}

# Function to install dependencies
install_dependencies() {
    log INFO "开始检查和安装依赖"
    echo -e "${BLUE}检查和安装依赖项${NC}"
    local update_needed=0
    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        update_needed=1
    fi

    if [[ $update_needed -eq 1 ]]; then
        echo -e "${CYAN}更新软件包列表...${NC}"
        log INFO "执行 apt update"
        apt update || { 
            log ERROR "apt update 失败"
            echo -e "${RED}错误: apt update 失败，请检查网络和软件源${NC}"
            exit 1
        }
    else
        echo -e "${GREEN}软件包列表已是最新${NC}"
    fi

    local packages_to_install=()
    if ! command -v curl >/dev/null 2>&1; then
        packages_to_install+=("curl")
    fi
    if ! command -v jq >/dev/null 2>&1; then
        packages_to_install+=("jq")
    fi

    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        echo -e "${CYAN}安装缺失的依赖: ${packages_to_install[*]}...${NC}"
        log INFO "安装软件包: ${packages_to_install[*]}"
        apt install -y "${packages_to_install[@]}" || { 
            log ERROR "安装依赖失败: ${packages_to_install[*]}"
            echo -e "${RED}错误: 安装依赖失败 (${packages_to_install[*]})${NC}"
            exit 1
        }
        log SUCCESS "依赖安装成功"
        echo -e "${GREEN}依赖安装成功${NC}"
    else
        echo -e "${GREEN}所有必需的依赖 (curl, jq) 已安装${NC}"
    fi
}

# 配置备份函数
backup_config() {
    log INFO "开始备份配置文件"
    
    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        echo -e "${YELLOW}没有找到配置文件，跳过备份${NC}"
        return 1
    fi
    
    # 创建备份目录
    mkdir -p "$BACKUP_DIR"
    
    # 生成备份文件名
    local backup_file="$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S).json"
    
    # 复制配置文件
    cp "$CONFIG_DIR/config.json" "$backup_file"
    
    if [[ $? -eq 0 ]]; then
        log SUCCESS "配置备份成功: $backup_file"
        echo -e "${GREEN}配置已备份到: $backup_file${NC}"
        
        # 保留最近10个备份
        local backup_count=$(ls -1 "$BACKUP_DIR"/config_*.json 2>/dev/null | wc -l)
        if [[ $backup_count -gt 10 ]]; then
            ls -1t "$BACKUP_DIR"/config_*.json | tail -n +11 | xargs rm -f
            log INFO "清理旧备份文件"
        fi
    else
        log ERROR "备份失败"
        echo -e "${RED}备份失败${NC}"
        return 1
    fi
}

# 配置恢复函数
restore_config() {
    log INFO "开始恢复配置"
    
    # 检查备份目录
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z $(ls -A "$BACKUP_DIR" 2>/dev/null) ]]; then
        echo -e "${YELLOW}没有找到可用的备份文件${NC}"
        return 1
    fi
    
    echo -e "${BLUE}可用的备份文件:${NC}"
    
    # 列出所有备份
    local backups=($(ls -1t "$BACKUP_DIR"/config_*.json 2>/dev/null))
    local count=0
    
    for backup in "${backups[@]}"; do
        count=$((count + 1))
        local backup_name=$(basename "$backup")
        local backup_time=$(echo "$backup_name" | sed 's/config_//g' | sed 's/.json//g' | sed 's/_/ /g')
        echo -e "  ${CYAN}$count) $backup_time${NC}"
    done
    
    # 选择备份
    echo -ne "${YELLOW}请选择要恢复的备份 [1-$count]: ${NC}"
    read -r choice
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [[ $choice -lt 1 ]] || [[ $choice -gt $count ]]; then
        echo -e "${RED}无效的选择${NC}"
        return 1
    fi
    
    local selected_backup="${backups[$((choice-1))]}"
    
    # 确认恢复
    if confirm_action "确定要恢复此备份吗？当前配置将被覆盖"; then
        # 备份当前配置
        if [[ -f "$CONFIG_DIR/config.json" ]]; then
            backup_config
        fi
        
        # 恢复配置
        cp "$selected_backup" "$CONFIG_DIR/config.json"
        
        if [[ $? -eq 0 ]]; then
            log SUCCESS "配置恢复成功"
            echo -e "${GREEN}配置恢复成功${NC}"
            
            # 重启服务
            echo -e "${CYAN}正在重启服务...${NC}"
            systemctl restart sing-box
            
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}服务重启成功${NC}"
            else
                echo -e "${RED}服务重启失败，请手动检查${NC}"
            fi
        else
            log ERROR "配置恢复失败"
            echo -e "${RED}配置恢复失败${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}已取消恢复${NC}"
    fi
}

# 健康检查函数
health_check() {
    echo -e "\n${BLUE}Sing-Box 健康检查${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    
    local issues=0
    
    # 检查服务状态
    echo -ne "${CYAN}服务状态... ${NC}"
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ 运行中${NC}"
    else
        echo -e "${RED}✗ 未运行${NC}"
        issues=$((issues + 1))
    fi
    
    # 检查配置文件
    echo -ne "${CYAN}配置文件... ${NC}"
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        if sing-box check -c "$CONFIG_DIR/config.json" &>/dev/null; then
            echo -e "${GREEN}✓ 有效${NC}"
        else
            echo -e "${RED}✗ 配置错误${NC}"
            issues=$((issues + 1))
        fi
    else
        echo -e "${RED}✗ 不存在${NC}"
        issues=$((issues + 1))
    fi
    
    # 检查端口监听
    echo -ne "${CYAN}端口监听... ${NC}"
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        local ports=$(jq -r '.inbounds[].listen_port' "$CONFIG_DIR/config.json" 2>/dev/null | sort -u)
        local listening_count=0
        local total_ports=0
        
        for port in $ports; do
            if [[ -n "$port" ]] && [[ "$port" != "null" ]]; then
                total_ports=$((total_ports + 1))
                if ss -tuln | grep -q ":$port "; then
                    listening_count=$((listening_count + 1))
                fi
            fi
        done
        
        if [[ $total_ports -gt 0 ]]; then
            if [[ $listening_count -eq $total_ports ]]; then
                echo -e "${GREEN}✓ 所有端口正常 ($listening_count/$total_ports)${NC}"
            else
                echo -e "${YELLOW}⚠ 部分端口异常 ($listening_count/$total_ports)${NC}"
                issues=$((issues + 1))
            fi
        else
            echo -e "${YELLOW}⚠ 无端口配置${NC}"
        fi
    else
        echo -e "${RED}✗ 无法检查${NC}"
    fi
    
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    
    # 结果汇总
    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}状态: 一切正常${NC}"
    else
        echo -e "${YELLOW}状态: 发现 $issues 个问题${NC}"
    fi
}

# 系统优化函数
optimize_system() {
    echo -e "\n${BLUE}系统优化${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    
    log INFO "开始系统优化"
    
    # BBR 加速
    echo -e "${CYAN}启用 BBR 加速...${NC}"
    
    # 检查内核版本
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)
    
    if [[ $major -gt 4 ]] || ([[ $major -eq 4 ]] && [[ $minor -ge 9 ]]); then
        # 启用 BBR
        if ! sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
            sysctl -p &>/dev/null
            
            if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
                echo -e "${GREEN}✓ BBR 启用成功${NC}"
                log SUCCESS "BBR 启用成功"
            else
                echo -e "${YELLOW}⚠ BBR 启用失败${NC}"
                log WARN "BBR 启用失败"
            fi
        else
            echo -e "${GREEN}✓ BBR 已启用${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ 内核版本过低，无法启用 BBR${NC}"
        log WARN "内核版本过低: $kernel_version"
    fi
    
    # 系统参数优化
    echo -e "${CYAN}优化系统参数...${NC}"
    
    cat >> /etc/sysctl.conf <<EOF
# Sing-Box 优化参数
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=10000 65000
net.ipv4.tcp_max_syn_backlog=8192
net.core.netdev_max_backlog=8192
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_mtu_probing=1
EOF
    
    sysctl -p &>/dev/null
    echo -e "${GREEN}✓ 系统参数优化完成${NC}"
    log SUCCESS "系统参数优化完成"
    
    # 防火墙配置
    echo -e "${CYAN}配置防火墙规则...${NC}"
    
    if command -v ufw &>/dev/null; then
        # 如果使用 ufw
        if [[ -f "$CONFIG_DIR/config.json" ]]; then
            local ports=$(jq -r '.inbounds[].listen_port' "$CONFIG_DIR/config.json" 2>/dev/null | sort -u)
            for port in $ports; do
                if [[ -n "$port" ]] && [[ "$port" != "null" ]]; then
                    ufw allow $port/tcp &>/dev/null
                    ufw allow $port/udp &>/dev/null
                fi
            done
            echo -e "${GREEN}✓ 防火墙规则已更新${NC}"
        fi
    elif command -v iptables &>/dev/null; then
        # 如果使用 iptables
        echo -e "${YELLOW}⚠ 请手动配置 iptables 规则${NC}"
    fi
    
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}系统优化完成${NC}"
}

# Function to get IP information
get_ip_info() {
    echo -e "\n${BLUE}Fetching IP Information${NC}"
    echo -e "${CYAN}Attempting to fetch IPv4 address from Cloudflare...${NC}"
    ipv4_address=$(curl -4sfS https://speed.cloudflare.com/meta | jq -r '.clientIp // empty' 2>/dev/null)
    echo -e "${CYAN}Attempting to fetch IPv6 address from Cloudflare...${NC}"
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
        echo -e "${CYAN}Detected Public IPs: ${NC}${display_ip_info}"
    fi

    local geoip_info
    echo -e "${CYAN}Fetching GeoIP information for ${primary_ip}...${NC}"
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

# Function to check TLS 1.3 support for a domain
check_tls13_support() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        return 1
    fi
    
    # Use curl to test TLS 1.3 support with timeout
    local result=$(curl -s -m 10 --tlsv1.3 --tls-max 1.3 -I "https://$domain" 2>/dev/null | head -1)
    if [[ -n "$result" ]] && echo "$result" | grep -q "HTTP"; then
        return 0
    fi
    return 1
}

# Function to validate SNI domains and populate VALID_TLS13_DOMAINS
validate_sni_domains() {
    echo -e "${CYAN}正在验证 TLS 1.3 域名支持...${NC}"
    
    # Define all potential SNI domains
    local domains=(
        "p11.douyinpic.com"
        "mp.weixin.qq.com"
        "coding.net"
        "upyun.com"
        "sns-video-hw.xhscdn.com"
        "sns-video-qn.xhscdn.com"
        "p6-dy.byteimg.com"
        "feishu.cn"
        "douyin.com"
        "toutiao.com"
        "v6-dy-y.ixigua.com"
        "hls3-akm.douyucdn.cn"
        "publicassets.cdn-apple.com"
        "weather-data.apple.com"
        "gateway.icloud.com"
    )
    
    # Reset the valid domains string
    VALID_TLS13_DOMAINS=""
    local valid_count=0
    local total_count=${#domains[@]}
    
    for domain in "${domains[@]}"; do
        echo -ne "${CYAN}检查 $domain...${NC} "
        if check_tls13_support "$domain"; then
            echo -e "${GREEN}✓${NC}"
            if [[ -n "$VALID_TLS13_DOMAINS" ]]; then
                VALID_TLS13_DOMAINS="$VALID_TLS13_DOMAINS $domain"
            else
                VALID_TLS13_DOMAINS="$domain"
            fi
            valid_count=$((valid_count + 1))
        else
            echo -e "${RED}✗${NC}"
        fi
    done
    
    echo -e "${GREEN}TLS 1.3 验证完成: $valid_count/$total_count 个域名可用${NC}"
    
    # Fallback if no domains are valid (network issues, etc.)
    if [[ -z "$VALID_TLS13_DOMAINS" ]]; then
        echo -e "${YELLOW}警告: 无法验证任何域名的 TLS 1.3 支持，使用默认域名${NC}"
        VALID_TLS13_DOMAINS="p11.douyinpic.com gateway.icloud.com"
    fi
}

# Function to output node information
output_node_info() {
    echo -e "\n${BLUE}Generated Node Information (Surge Format)${NC}"
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

        # Check if there's a separated UDP port and compare with ShadowTLS port
        if [[ $separated_udp_exists -eq 0 ]]; then
            local udp_port
            udp_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks" and .network == "udp" and .listen != "127.0.0.1") | .listen_port' /etc/sing-box/config.json)
            
            # Check if UDP port is actually different from ShadowTLS port
            if [[ "$udp_port" != "$stls_port" ]]; then
                # Truly separated ports
                echo -e "${CYAN}${country_code} [ss2022][shadow-tls-v3][separated-ports]${NC} = ${MAGENTA}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true, udp-port=${udp_port}${NC}"
                
                echo -e "\n${BLUE}Optional Configurations${NC}"
                echo -e "${CYAN}${country_code} [ss2022][TCP-only]${NC} = ${MAGENTA}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=false${NC}"
                echo -e "${CYAN}${country_code} [ss2022][UDP-only]${NC} = ${MAGENTA}ss, ${primary_ip}, ${udp_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
                
                echo -e "\n${YELLOW}Note: Separated ports configuration - TCP via ShadowTLS obfuscation (${stls_port}), UDP direct (${udp_port})${NC}"
            else
                # Same port but configured as UDP separate listener (should be treated as shared)
                echo -e "${CYAN}${country_code} [ss2022][shadow-tls-v3][shared-port]${NC} = ${MAGENTA}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true${NC}"
                
                echo -e "\n${YELLOW}Note: Shared port configuration - Both TCP and UDP use port ${stls_port} (experimental feature)${NC}"
            fi
        else
            # No separated UDP configuration - shared port
            echo -e "${CYAN}${country_code} [ss2022][shadow-tls-v3][shared-port]${NC} = ${MAGENTA}ss, ${primary_ip}, ${stls_port}, encrypt-method=${ss_method}, password=${ss_pwd}, shadow-tls-password=${shadowtls_pwd}, shadow-tls-sni=${sni}, shadow-tls-version=3, udp-relay=true${NC}"
            
            echo -e "\n${YELLOW}Note: Shared port configuration - Both TCP and UDP use port ${stls_port} (experimental feature)${NC}"
        fi
        
        # Output for direct internal Shadowsocks
        local internal_ss_port
        internal_ss_port=$(jq -r '.inbounds[] | select(.type == "shadowsocks" and .listen == "127.0.0.1") | .listen_port' /etc/sing-box/config.json)
        if [[ -n "$internal_ss_port" && "$internal_ss_port" != "null" ]]; then
            echo -e "\n${BLUE}Internal Shadowsocks Port (For debugging)${NC}"
            echo -e "${CYAN}${country_code} [ss2022][internal]${NC} = ${MAGENTA}ss, ${primary_ip}, ${internal_ss_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
        fi
        
    else # Only Shadowsocks is configured (Pure SS mode)
        echo -e "${CYAN}${country_code} [ss2022][pure-ss]${NC} = ${MAGENTA}ss, ${primary_ip}, ${primary_ss_port}, encrypt-method=${ss_method}, password=${ss_pwd}, udp-relay=true${NC}"
        echo -e "\n${YELLOW}Note: Pure Shadowsocks configuration - Direct listening on port ${primary_ss_port}, no TLS obfuscation${NC}"
    fi
    
    echo -e "\n${YELLOW}Make sure your client supports the specified parameters. Adjust configuration if necessary.${NC}"
}

# Function to format and validate sing-box configuration
format_config() {
    local temp_file="/tmp/config.json.$$" 
    echo -e "${CYAN}Formatting configuration file with 'sing-box format'...${NC}"
    if sing-box format -c /etc/sing-box/config.json > "$temp_file"; then
        echo -e "${CYAN}Validating formatted configuration with 'sing-box check'...${NC}"
        if sing-box check -c "$temp_file"; then
            chown sing-box:sing-box "$temp_file"
            chmod 640 "$temp_file"
            mv "$temp_file" /etc/sing-box/config.json
            echo -e "${GREEN}Configuration formatted and validated successfully.${NC}"
            return 0
        else
            echo -e "${RED}Error: Configuration validation failed after formatting.${NC}"
            # Consider adding a prompt or instruction here, e.g., how to view the temp file
            echo -e "${YELLOW}Attempting to display the invalid temporary configuration file ($temp_file):${NC}"
            cat "$temp_file" 
            echo -e "${YELLOW}End of temporary configuration file.${NC}"
            rm -f "$temp_file"
            return 1
        fi
    else
        echo -e "${RED}Error: Configuration formatting failed.${NC}"
        # Consider adding a prompt or instruction here as well
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

    echo -e "\n${BLUE}Deployment Mode Selection${NC}"
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
            echo -e "${GREEN}Selected: ${MAGENTA}${deployment_name}${NC}"
            ;;
        3) 
            use_shadowtls=2
            deployment_name="ShadowTLS + Shared Port"
            echo -e "${GREEN}Selected: ${MAGENTA}${deployment_name}${NC} ${YELLOW}(Experimental feature)${NC}"
            ;;
        *) 
            use_shadowtls=1
            deployment_name="ShadowTLS + Separated Ports"
            echo -e "${GREEN}Selected: ${MAGENTA}${deployment_name}${NC} ${GREEN}(Recommended)${NC}"
            ;;
    esac

    ARCH=$(get_arch)
    echo -e "${CYAN}Detected Architecture: ${MAGENTA}$ARCH${NC}"

    echo -e "${CYAN}Fetching latest Sing-Box beta version from GitHub...${NC}"
    VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases | jq -r '.[] | select(.prerelease == true) | .tag_name' | head -n1 | sed 's/v//')
    if [[ -z "$VERSION" ]]; then
        echo -e "${RED}Error: Could not fetch the latest beta version tag from GitHub.${NC}"
        echo -e "${YELLOW}Please check your internet connection or GitHub API rate limits.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Latest Sing-Box beta version: ${MAGENTA}$VERSION${NC}"

    echo -e "${CYAN}Downloading Sing-Box beta ${MAGENTA}$VERSION${CYAN} for ${MAGENTA}$ARCH${CYAN}...${NC}"
    curl -Lo sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box_${VERSION}_linux_${ARCH}.deb"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Failed to download Sing-Box .deb package.${NC}"
        rm -f sing-box.deb
        exit 1
    fi

    echo -e "${CYAN}Installing Sing-Box package (sing-box.deb)...${NC}"
    dpkg -i sing-box.deb
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Failed to install Sing-Box package using dpkg.${NC}"
        echo -e "${YELLOW}You may need to resolve dependencies manually (e.g., 'sudo apt --fix-broken install').${NC}"
        rm -f sing-box.deb
        exit 1
    fi
    rm -f sing-box.deb
    echo -e "${GREEN}Sing-Box package installed successfully.${NC}"

    echo -e "\n${BLUE}Verifying/Setting up 'sing-box' User and Directories${NC}"
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

    echo -e "${CYAN}Configuring directory: /etc/sing-box${NC}"
    if [ ! -d "/etc/sing-box" ]; then
        mkdir -p /etc/sing-box
        echo -e "${YELLOW}/etc/sing-box directory created.${NC}"
    fi
    chown -R sing-box:sing-box /etc/sing-box
    chmod 750 /etc/sing-box 

    echo -e "${CYAN}Configuring directory: /var/lib/sing-box${NC}"
    if [ ! -d "/var/lib/sing-box" ]; then
        mkdir -p /var/lib/sing-box
        echo -e "${YELLOW}/var/lib/sing-box directory created.${NC}"
    fi
    chown -R sing-box:sing-box /var/lib/sing-box
    chmod 750 /var/lib/sing-box 

    echo -e "\n${BLUE}Initial Sing-Box Configuration${NC}"
    rm -f /etc/sing-box/config.json 

    echo -e "\n${BLUE}ShadowSocks Settings${NC}"
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
    echo -e "${GREEN}Using Shadowsocks method: ${MAGENTA}$ss_method${NC}"

    # Shadowsocks password settings
    echo -e "\n${YELLOW}Shadowsocks password configuration:${NC}"
    echo -e "  ${CYAN}- Enter custom password${NC}"
    echo -e "  ${CYAN}- Press Enter for random password${NC}"
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
        echo -e "  ${CYAN}- Enter custom password${NC}"
        echo -e "  ${CYAN}- Press Enter for random password${NC}"
        read -p "$(echo -e "${YELLOW}Enter ShadowTLS password (Press Enter for random): ${NC}")" shadowtls_pwd
        
        if [[ -z "$shadowtls_pwd" ]]; then
            shadowtls_pwd=$(openssl rand -base64 32)
            echo -e "${GREEN}Generated random ShadowTLS password.${NC}"
        else
            echo -e "${GREEN}Using custom ShadowTLS password.${NC}"
        fi
    fi

    echo -e "\n${BLUE}Port Configuration${NC}"
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
    echo -e "  ${CYAN}- Enter port number (10000-65535)${NC}"
    echo -e "  ${CYAN}- Press Enter for random port${NC}"
    read -p "$(echo -e "${YELLOW}Set ${port_prompt_text} (Press Enter for random): ${NC}")" port
    
    if [[ -z "$port" ]]; then
        port=$(shuf -i 10000-65535 -n 1)
        echo -e "${CYAN}Generated random port: ${MAGENTA}$port${NC}"
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
            echo -e "${CYAN}Generated random port: ${MAGENTA}$port${NC}"
        fi
    done
    
    echo -e "${GREEN}Will use port ${MAGENTA}$port${GREEN} for ${MAGENTA}${deployment_name}${GREEN}.${NC}"
    
    # Internal SS port and UDP port configuration
    local ss_port_internal="" # Internal SS port for ShadowTLS modes
    local udp_port="" # Separated UDP port for mode 1
    
    if [[ $use_shadowtls -eq 1 ]]; then  # ShadowTLS + Separated Ports
        ss_port_internal=$(shuf -i 10000-65535 -n 1)
        until [[ $ss_port_internal != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port_internal") ]]; do
            ss_port_internal=$(shuf -i 10000-65535 -n 1)
        done
        echo -e "${GREEN}Will use port ${MAGENTA}$ss_port_internal${GREEN} for Shadowsocks (internal TCP).${NC}"
        
        udp_port=$((port + 1))
        until [[ -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$udp_port") ]]; do
            udp_port=$((udp_port + 1))
            if [[ $udp_port -gt 65535 ]]; then
                udp_port=$(shuf -i 10000-65535 -n 1)
            fi
        done
        echo -e "${GREEN}Will use port ${MAGENTA}$udp_port${GREEN} for Shadowsocks (direct UDP).${NC}"
        
    elif [[ $use_shadowtls -eq 2 ]]; then  # ShadowTLS + Shared Port
        ss_port_internal=$(shuf -i 10000-65535 -n 1)
        until [[ $ss_port_internal != $port && -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$ss_port_internal") ]]; do
            ss_port_internal=$(shuf -i 10000-65535 -n 1)
        done
        echo -e "${GREEN}Will use port ${MAGENTA}$ss_port_internal${GREEN} for Shadowsocks (internal TCP).${NC}"
        echo -e "${YELLOW}Will attempt to use port ${MAGENTA}$port${YELLOW} for UDP (experimental - may conflict).${NC}"
    fi

    echo -e "\n${BLUE}ShadowTLS Handshake Settings${NC}"
    local proxysite=""
    local wildcard_sni=""
    if [[ $use_shadowtls -gt 0 ]]; then
        echo -e "\n${CYAN}Performing TLS 1.3 validation for SNI domains...${NC}"
        validate_sni_domains
        
        # Build dynamic SNI menu based on validated domains
        echo -e "\n${YELLOW}Select ShadowTLS SNI (TLS 1.3 verified domains only):${NC}"
        
        # Define all domains with their info (TLS 1.3 verified)
        declare -A all_sni_domains=(
            ["p11.douyinpic.com"]="Douyin Image CDN - Default"
            ["mp.weixin.qq.com"]="WeChat"
            ["coding.net"]="Coding.net"
            ["upyun.com"]="UpYun CDN"
            ["sns-video-hw.xhscdn.com"]="XiaoHongShu Video"
            ["sns-video-qn.xhscdn.com"]="XiaoHongShu Video"
            ["p6-dy.byteimg.com"]="ByteDance CDN"
            ["feishu.cn"]="Feishu/Lark"
            ["douyin.com"]="Douyin"
            ["toutiao.com"]="Toutiao"
            ["v6-dy-y.ixigua.com"]="Ixigua Video"
            ["hls3-akm.douyucdn.cn"]="Douyu CDN"
            ["publicassets.cdn-apple.com"]="Apple CDN"
            ["weather-data.apple.com"]="Apple Weather"
            ["gateway.icloud.com"]="iCloud Gateway - Most Stable"
        )
        
        # Convert VALID_TLS13_DOMAINS to array
        read -ra valid_domains_array <<< "$VALID_TLS13_DOMAINS"
        
        # Build menu
        declare -a menu_domains=()
        local menu_index=1
        declare -A choice_to_domain=()
        
        for domain in "${valid_domains_array[@]}"; do
            if [[ -n "$domain" ]]; then
                echo -e "  ${CYAN}$menu_index) $domain (${all_sni_domains[$domain]}) ${GREEN}✓${NC}"
                choice_to_domain[$menu_index]="$domain"
                menu_domains+=("$domain")
                ((menu_index++))
            fi
        done
        
        echo -e "  ${CYAN}$menu_index) Custom domain${NC}"
        
        # Set default to first valid domain or fallback
        local default_domain="${valid_domains_array[0]}"
        if [[ -z "$default_domain" ]]; then
            default_domain="p11.douyinpic.com"
        fi
        
        read -p "$(echo -e "${YELLOW}Enter your choice [1-$menu_index] (Default: 1 - $default_domain): ${NC}")" sni_choice
        
        if [[ "$sni_choice" == "$menu_index" ]]; then
            # Custom domain
            read -p "$(echo -e "${YELLOW}Enter custom domain: ${NC}")" proxysite
            if [[ -z "$proxysite" ]]; then
                proxysite="$default_domain"
            fi
            # Optionally verify custom domain
            echo -e "${CYAN}Verifying custom domain TLS 1.3 support...${NC}"
            if check_tls13_support "$proxysite"; then
                echo -e "${GREEN}✓ Custom domain $proxysite supports TLS 1.3${NC}"
            else
                echo -e "${YELLOW}⚠ Warning: Custom domain $proxysite may not support TLS 1.3${NC}"
            fi
        elif [[ -n "${choice_to_domain[$sni_choice]}" ]]; then
            proxysite="${choice_to_domain[$sni_choice]}"
        else
            # Invalid choice or empty, use default
            proxysite="$default_domain"
        fi
        
        echo -e "${GREEN}Using SNI: ${MAGENTA}$proxysite${NC}"

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
        echo -e "${GREEN}Using wildcard_sni mode: ${MAGENTA}$wildcard_sni${NC}"
    fi

    echo -e "\n${BLUE}DNS Strategy Configuration${NC}"
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
             echo -e "${YELLOW}Auto-selecting the only available option: ${MAGENTA}${options[0]}${NC}"
        fi
        prompt_text+=": ${NC}"

        if [[ ${#options[@]} -gt 1 ]]; then
            read -p "$(echo -e "$prompt_text")" strategy_choice
        fi

        if [[ -z "$strategy_choice" && $default_option_idx -ne -1 ]]; then
            default_strategy="${option_tags[$default_option_idx]}"
            echo -e "${YELLOW}No input, using default: ${MAGENTA}${options[$default_option_idx]}${NC}"
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
            echo -e "${YELLOW}Invalid choice or auto-selected. Using strategy: ${MAGENTA}$default_strategy${NC}"
        fi
    fi
    echo -e "${GREEN}Using DNS strategy: ${MAGENTA}$default_strategy${NC}"

    echo -e "\n${BLUE}Generating Configuration File${NC}"

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
            inbounds_json+=$(cat << INNER_EOF
,
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-udp",
            "listen": "::",
            "listen_port": $udp_port,
            "network": "udp",
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
INNER_EOF
)
        elif [[ $use_shadowtls -eq 2 ]]; then
            # Shared port UDP (experimental)
            inbounds_json+=$(cat << INNER_EOF
,
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-udp",
            "listen": "::",
            "listen_port": $port,
            "network": "udp",
            "method": "$ss_method",
            "password": "$ss_pwd"
        }
INNER_EOF
)
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
                "tag": "dns_fakeip",
                "type": "fakeip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            },
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
            },
            {
                "tag": "dns_block",
                "type": "hosts",
                "mapping": {}
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
                "rule_set": ["geosite-netflix", "geosite-disney", "geosite-category-media"],
                "server": "dns_fakeip",
                "query_type": ["A", "AAAA"]
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

    echo -e "\n${BLUE}Formatting and Validating Configuration${NC}"
    if ! format_config; then
        echo -e "${RED}Critical Error: Halting installation due to configuration error. Please check messages above.${NC}"
        echo -e "${YELLOW}The file /etc/sing-box/config.json may be invalid or an intermediate temp file might remain in /tmp/.${NC}"
        exit 1
    fi

    echo -e "\n${BLUE}Starting and Enabling Sing-Box Service${NC}"
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
    echo -e "\n${BLUE}Uninstalling Sing-Box${NC}"
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${CYAN}Stopping Sing-Box service...${NC}"
        systemctl stop sing-box
    fi
    
    if systemctl is-enabled --quiet sing-box; then
        echo -e "${CYAN}Disabling Sing-Box service...${NC}"
        systemctl disable sing-box
    fi
    
    if [[ -f /etc/systemd/system/sing-box.service ]]; then
        echo -e "${CYAN}Removing Sing-Box service file...${NC}"
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload
    fi
    
    if [[ -d /etc/sing-box ]]; then
        echo -e "${CYAN}Removing configuration directory (/etc/sing-box)...${NC}"
        rm -rf /etc/sing-box
    fi
    
    if [[ -f /usr/local/bin/sing-box ]]; then
        echo -e "${CYAN}Removing Sing-Box binary (/usr/local/bin/sing-box)...${NC}"
        rm -f /usr/local/bin/sing-box
    fi

    if [[ -d /var/lib/sing-box ]]; then
        echo -e "${CYAN}Removing Sing-Box data directory (/var/lib/sing-box)...${NC}"
        rm -rf /var/lib/sing-box
    fi
    
    if id "sing-box" &>/dev/null; then
        echo -e "${CYAN}Removing sing-box user...${NC}"
        userdel -r sing-box 2>/dev/null || echo -e "${YELLOW}Warning: Failed to remove sing-box user. It might have already been removed or a home directory issue exists.${NC}"
    fi

    if getent group sing-box > /dev/null 2>&1; then
        echo -e "${CYAN}Removing sing-box group...${NC}"
        groupdel sing-box 2>/dev/null || echo -e "${YELLOW}Warning: Failed to remove sing-box group. It might have already been removed.${NC}"
    fi
    
    echo -e "${GREEN}Sing-Box has been successfully uninstalled.${NC}"
}

# Function to change port
change_port() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}Change Port Configuration${NC}"
    
    local shadowtls_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    local separated_udp_exists=$(jq -e '.inbounds[] | select(.type == "shadowsocks" and .network == "udp" and .listen != "127.0.0.1")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    
    local mode_name=""
    local target_tag=""
    local service_name_display="" # For display purposes
    local is_shared_port_change=0
    local config_path_filter="" # jq path filter for updating

    if [[ $shadowtls_exists -ne 0 ]]; then # Pure SS mode
        mode_name="Pure Shadowsocks"
        echo -e "${CYAN}Current mode: ${mode_name}${NC}"
        service_name_display="Shadowsocks (TCP/UDP)"
        local current_port=$(jq -r --arg type_val "shadowsocks" '.inbounds[] | select(.type == $type_val) | .listen_port' /etc/sing-box/config.json | head -1)
        echo -e "${CYAN}Current $service_name_display listening port: ${MAGENTA}$current_port${NC}"
        
        read -p "$(echo -e "${YELLOW}Please enter new $service_name_display port (10000-65535, Enter for random): ${NC}")" new_port
        if [[ -z "$new_port" ]]; then
            new_port=$(shuf -i 10000-65535 -n 1)
            echo -e "${CYAN}Generated random port: ${MAGENTA}$new_port${NC}"
        fi
        if ! validate_and_check_port "$new_port" "$current_port"; then return 1; fi
        config_path_filter="(.inbounds[] | select(.type == \"shadowsocks\") | .listen_port) = $new_port"

    elif [[ $separated_udp_exists -eq 0 ]]; then # ShadowTLS + Separated UDP mode
        mode_name="ShadowTLS + Separated Ports"
        echo -e "${CYAN}Current mode: ${mode_name}${NC}"
        echo -e "${YELLOW}Which port would you like to modify?${NC}"
        echo -e "  ${CYAN}1) ShadowTLS (TCP obfuscation) port${NC}"
        echo -e "  ${CYAN}2) Shadowsocks internal TCP port (usually no need to change)${NC}"
        echo -e "  ${CYAN}3) Shadowsocks separated UDP port${NC}"
        read -p "$(echo -e "${YELLOW}Please enter option [1-3]: ${NC}")" port_choice

        local current_port=""
        case "$port_choice" in
            1) target_tag="shadowtls-in"; service_name_display="ShadowTLS (TCP obfuscation)"
               config_path_filter="(.inbounds[] | select(.tag == \"shadowtls-in\") | .listen_port) = %NEW_PORT%"
               ;; 
            2) target_tag="shadowsocks-in"; service_name_display="Shadowsocks internal TCP" 
               config_path_filter="(.inbounds[] | select(.tag == \"shadowsocks-in\" and .listen == \"127.0.0.1\") | .listen_port) = %NEW_PORT%"
               ;; 
            3) target_tag="shadowsocks-udp"; service_name_display="Shadowsocks separated UDP"
               config_path_filter="(.inbounds[] | select(.tag == \"shadowsocks-udp\") | .listen_port) = %NEW_PORT%"
               ;; 
            *) echo -e "${RED}Invalid option.${NC}"; return 1;;
        esac
        
        if [[ "$target_tag" == "shadowsocks-in" ]]; then
             current_port=$(jq -r --arg tag_val "$target_tag" '.inbounds[] | select(.tag == $tag_val and .listen == "127.0.0.1") | .listen_port' /etc/sing-box/config.json)
        else
             current_port=$(jq -r --arg tag_val "$target_tag" '.inbounds[] | select(.tag == $tag_val) | .listen_port' /etc/sing-box/config.json)
        fi
        echo -e "${CYAN}Current $service_name_display port: ${MAGENTA}$current_port${NC}"
        read -p "$(echo -e "${YELLOW}Please enter new $service_name_display port (10000-65535, Enter for random): ${NC}")" new_port
        if [[ -z "$new_port" ]]; then
            new_port=$(shuf -i 10000-65535 -n 1)
            echo -e "${CYAN}Generated random port: ${MAGENTA}$new_port${NC}"
        fi
        if ! validate_and_check_port "$new_port" "$current_port"; then return 1; fi
        config_path_filter=${config_path_filter//%NEW_PORT%/$new_port} # Substitute placeholder

    else # ShadowTLS + Shared Port mode
        mode_name="ShadowTLS + Shared Port"
        echo -e "${CYAN}Current mode: ${mode_name}${NC}"
        echo -e "${YELLOW}Which port would you like to modify?${NC}"
        echo -e "  ${CYAN}1) ShadowTLS and Shadowsocks UDP shared port${NC}"
        echo -e "  ${CYAN}2) Shadowsocks internal TCP port (usually no need to change)${NC}"
        read -p "$(echo -e "${YELLOW}Please enter option [1-2]: ${NC}")" port_choice
        
        local current_port=""
        case "$port_choice" in
            1) 
                service_name_display="ShadowTLS/UDP shared"
                is_shared_port_change=1
                current_port=$(jq -r --arg tag_val "shadowtls-in" '.inbounds[] | select(.tag == $tag_val) | .listen_port' /etc/sing-box/config.json)
                ;;
            2) 
                target_tag="shadowsocks-in" 
                service_name_display="Shadowsocks internal TCP"
                current_port=$(jq -r --arg tag_val "$target_tag" '.inbounds[] | select(.tag == $tag_val and .listen == "127.0.0.1") | .listen_port' /etc/sing-box/config.json)
                config_path_filter="(.inbounds[] | select(.tag == \"shadowsocks-in\" and .listen == \"127.0.0.1\") | .listen_port) = %NEW_PORT%"
                ;;
            *) echo -e "${RED}Invalid option.${NC}"; return 1;;
        esac
        
        echo -e "${CYAN}Current $service_name_display port: ${MAGENTA}$current_port${NC}"
        
        read -p "$(echo -e "${YELLOW}Please enter new $service_name_display port (10000-65535, Enter for random): ${NC}")" new_port
        if [[ -z "$new_port" ]]; then
            new_port=$(shuf -i 10000-65535 -n 1)
            echo -e "${CYAN}Generated random port: ${MAGENTA}$new_port${NC}"
        fi

        if ! validate_and_check_port "$new_port" "$current_port"; then return 1; fi

        if [[ $is_shared_port_change -eq 1 ]]; then
            config_path_filter="(.inbounds[] | select(.tag == \"shadowtls-in\") | .listen_port) = $new_port | (.inbounds[] | select(.tag == \"shadowsocks-udp\") | .listen_port) = $new_port"
        else 
            config_path_filter=${config_path_filter//%NEW_PORT%/$new_port}
        fi
    fi
    
    jq "$config_path_filter" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Port update failed. Check jq command and file permissions.${NC}"
        return 1
    fi
    
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        return 1
    fi
    
    echo -e "${CYAN}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}Port successfully changed to ${MAGENTA}$new_port${GREEN}!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service restart failed.${NC}"
        return 1
    fi
}

# Helper function for port validation (to avoid repetition)
validate_and_check_port() {
    local port_to_validate=$1
    local current_port_val=$2 # Optional: current port value, to allow re-entering the same port

    if [[ "$port_to_validate" == "$current_port_val" ]]; then
        # Allowing to "change" to the same port is effectively a no-op for validation purposes here
        return 0
    fi

    if [[ ! "$port_to_validate" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Error: Port must be numeric.${NC}"
        return 1
    elif [[ "$port_to_validate" -lt 10000 || "$port_to_validate" -gt 65535 ]]; then
        echo -e "${RED}Error: Port must be between 10000-65535.${NC}"
        return 1
    elif [[ -n $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port_to_validate") ]]; then
        echo -e "${RED}Error: Port $port_to_validate is already in use by another process.${NC}"
        return 1
    fi
    return 0
}

# Function to change Shadowsocks UDP port
change_ss_udp_port() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi

    echo -e "\n${BLUE}Change Shadowsocks UDP Port${NC}"

    local shadowtls_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    local separated_udp_exists=$(jq -e '.inbounds[] | select(.type == "shadowsocks" and .network == "udp" and .listen != "127.0.0.1")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)

    local target_tag=""
    local current_udp_port=""
    local service_name_display="Shadowsocks UDP"
    local config_path_filter=""

    if [[ $shadowtls_exists -ne 0 ]]; then # Pure SS mode
        current_udp_port=$(jq -r --arg type_val "shadowsocks" '.inbounds[] | select(.type == $type_val) | .listen_port' /etc/sing-box/config.json | head -1)
        echo -e "${YELLOW}Pure Shadowsocks mode: TCP and UDP share port ${MAGENTA}$current_udp_port${YELLOW}.${NC}"
        echo -e "${YELLOW}Modifying this will change the main port for both TCP and UDP.${NC}"
        target_tag="shadowsocks-in" # Main SS inbound handles both
        config_path_filter="(.inbounds[] | select(.type == \"shadowsocks\") | .listen_port) = %NEW_PORT%"
        service_name_display="Shadowsocks (TCP/UDP)"

    elif [[ $separated_udp_exists -eq 0 ]]; then # ShadowTLS + Separated UDP
        target_tag="shadowsocks-udp"
        current_udp_port=$(jq -r --arg tag_val "$target_tag" '.inbounds[] | select(.tag == $tag_val) | .listen_port' /etc/sing-box/config.json)
        service_name_display="Shadowsocks separated UDP"
        config_path_filter="(.inbounds[] | select(.tag == \"shadowsocks-udp\") | .listen_port) = %NEW_PORT%"
    else # ShadowTLS + Shared Port
        current_udp_port=$(jq -r --arg tag_val "shadowtls-in" '.inbounds[] | select(.tag == $tag_val) | .listen_port' /etc/sing-box/config.json)
        echo -e "${YELLOW}Shared Port mode: UDP shares port ${MAGENTA}$current_udp_port${YELLOW} with ShadowTLS.${NC}"
        echo -e "${YELLOW}To modify this, use the main 'Port Settings' menu and choose 'ShadowTLS and Shadowsocks UDP shared port'.${NC}"
        echo -e "${YELLOW}This menu option will not make changes in this mode.${NC}"
        read -p "$(echo -e "${YELLOW}Press Enter to return...${NC}")"
        return 0
    fi
    
    echo -e "${CYAN}Current $service_name_display port: ${MAGENTA}$current_udp_port${NC}"
    
    read -p "$(echo -e "${YELLOW}Please enter new $service_name_display port (10000-65535, Enter for random): ${NC}")" new_port
    if [[ -z "$new_port" ]]; then
        new_port=$(shuf -i 10000-65535 -n 1)
        echo -e "${CYAN}Generated random port: ${MAGENTA}$new_port${NC}"
    fi

    if ! validate_and_check_port "$new_port" "$current_udp_port"; then return 1; fi
    
    config_path_filter=${config_path_filter//%NEW_PORT%/$new_port}
    jq "$config_path_filter" /etc/sing-box/config.json > /tmp/sing-box-temp.json
    
    if [[ $? -ne 0 || ! -f /tmp/sing-box-temp.json ]]; then
        echo -e "${RED}Port update failed (jq command execution error).${NC}"
        rm -f /tmp/sing-box-temp.json
        return 1
    fi
    mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        return 1
    fi
    
    echo -e "${CYAN}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}$service_name_display port successfully changed to ${MAGENTA}$new_port${GREEN}!${NC}"
        output_node_info
    else
        echo -e "${RED}Error: Service restart failed.${NC}"
        return 1
    fi
}

# Function to change passwords
change_passwords() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}Change Passwords${NC}"
    
    local shadowtls_exists=$(jq -e '.inbounds[] | select(.type == "shadowtls")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
    local current_ss_method=$(jq -r '.inbounds[] | select(.type == "shadowsocks") | .method' /etc/sing-box/config.json | head -1)

    if [[ $shadowtls_exists -eq 0 ]]; then
        echo -e "\n${YELLOW}ShadowTLS password configuration:${NC}"
        echo -e "  ${CYAN}- Enter custom password${NC}"
        echo -e "  ${CYAN}- Press Enter for random password${NC}"
        read -p "$(echo -e "${YELLOW}Please enter new ShadowTLS password (Press Enter for random): ${NC}")" shadowtls_password
        
        if [[ -z "$shadowtls_password" ]]; then
            shadowtls_password=$(openssl rand -base64 32)
            echo -e "${GREEN}Generated random ShadowTLS password.${NC}"
        fi
        
        jq "(.inbounds[] | select(.type == \"shadowtls\") | .users[0].password) = \"$shadowtls_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
        if [[ $? -ne 0 ]]; then echo -e "${RED}ShadowTLS password update failed.${NC}"; return 1; fi
        echo -e "${GREEN}ShadowTLS password updated.${NC}"
    fi
    
    echo -e "\n${YELLOW}Shadowsocks password configuration:${NC}"
    echo -e "  ${CYAN}- Enter custom password${NC}"
    echo -e "  ${CYAN}- Press Enter for random password${NC}"
    read -p "$(echo -e "${YELLOW}Please enter new Shadowsocks password (Press Enter for random): ${NC}")" shadowsocks_password
    
    if [[ -z "$shadowsocks_password" ]]; then
        case "$current_ss_method" in
            "2022-blake3-aes-128-gcm") shadowsocks_password=$(openssl rand -base64 16) ;; 
            "2022-blake3-aes-256-gcm"|"2022-blake3-chacha20-poly1305") shadowsocks_password=$(openssl rand -base64 32) ;; 
            *) shadowsocks_password=$(openssl rand -base64 32) ;; 
        esac
        echo -e "${GREEN}Generated random Shadowsocks password.${NC}"
    fi
    
    jq "(.inbounds[] | select(.type == \"shadowsocks\") | .password) = \"$shadowsocks_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then echo -e "${RED}Shadowsocks password update failed.${NC}"; return 1; fi
    echo -e "${GREEN}Shadowsocks password updated (applied to all SS configurations).${NC}"
    
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        return 1
    fi
    
    echo -e "${CYAN}Restarting Sing-Box service...${NC}"
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
    
    echo -e "\n${BLUE}Change ShadowTLS Password${NC}"
    echo -e "  ${CYAN}- Enter custom password${NC}"
    echo -e "  ${CYAN}- Press Enter for random password${NC}"
    read -p "$(echo -e "${YELLOW}Please enter new ShadowTLS password (Press Enter for random): ${NC}")" new_password
    
    if [[ -z "$new_password" ]]; then
        new_password=$(openssl rand -base64 32)
        echo -e "${GREEN}Generated random password.${NC}"
    fi
    
    jq "(.inbounds[] | select(.type == \"shadowtls\") | .users[0].password) = \"$new_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then echo -e "${RED}ShadowTLS password update failed.${NC}"; return 1; fi
        
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    
    if ! format_config; then
        echo -e "${RED}Error: Configuration file formatting or validation failed.${NC}"
        return 1
    fi
    
    echo -e "${CYAN}Restarting Sing-Box service...${NC}"
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
    
    echo -e "\n${BLUE}Change ShadowTLS SNI${NC}"
    
    local current_sni=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .handshake.server' /etc/sing-box/config.json)
    echo -e "${CYAN}Current SNI: $current_sni${NC}"
    
    # Perform TLS 1.3 validation
    echo -e "\n${CYAN}Performing TLS 1.3 validation for SNI domains...${NC}"
    validate_sni_domains
    
    # Build dynamic SNI menu based on validated domains
    echo -e "\n${CYAN}Select new SNI (TLS 1.3 verified domains only):${NC}"
    
    # Define all domains with their info (TLS 1.3 verified)
    declare -A all_sni_domains=(
        ["p11.douyinpic.com"]="Douyin Image CDN"
        ["mp.weixin.qq.com"]="WeChat"
        ["coding.net"]="Coding.net"
        ["upyun.com"]="UpYun CDN"
        ["sns-video-hw.xhscdn.com"]="XiaoHongShu Video"
        ["sns-video-qn.xhscdn.com"]="XiaoHongShu Video"
        ["p6-dy.byteimg.com"]="ByteDance CDN"
        ["feishu.cn"]="Feishu/Lark"
        ["douyin.com"]="Douyin"
        ["toutiao.com"]="Toutiao"
        ["v6-dy-y.ixigua.com"]="Ixigua Video"
        ["hls3-akm.douyucdn.cn"]="Douyu CDN"
        ["publicassets.cdn-apple.com"]="Apple CDN"
        ["weather-data.apple.com"]="Apple Weather"
        ["gateway.icloud.com"]="iCloud Gateway - Most Stable"
    )
    
    # Convert VALID_TLS13_DOMAINS to array
    read -ra valid_domains_array <<< "$VALID_TLS13_DOMAINS"
    
    # Build menu
    local menu_index=1
    declare -A choice_to_domain=()
    
    for domain in "${valid_domains_array[@]}"; do
        if [[ -n "$domain" ]]; then
            echo -e "  ${CYAN}$menu_index) $domain (${all_sni_domains[$domain]}) ${GREEN}✓${NC}"
            choice_to_domain[$menu_index]="$domain"
            ((menu_index++))
        fi
    done
    
    echo -e "  ${CYAN}$menu_index) Custom domain${NC}"
    
    # Set default to first valid domain or fallback
    local default_domain="${valid_domains_array[0]}"
    if [[ -z "$default_domain" ]]; then
        default_domain="p11.douyinpic.com"
    fi
    
    read -p "$(echo -e "${YELLOW}Enter your choice [1-$menu_index] (Default: 1 - $default_domain): ${NC}")" sni_choice
    
    local new_sni=""
    if [[ "$sni_choice" == "$menu_index" ]]; then
        # Custom domain
        read -p "$(echo -e "${YELLOW}Enter custom domain: ${NC}")" new_sni
        if [[ -z "$new_sni" ]]; then
            new_sni="$default_domain"
        fi
        # Verify custom domain
        echo -e "${CYAN}Verifying custom domain TLS 1.3 support...${NC}"
        if check_tls13_support "$new_sni"; then
            echo -e "${GREEN}✓ Custom domain $new_sni supports TLS 1.3${NC}"
        else
            echo -e "${YELLOW}⚠ Warning: Custom domain $new_sni may not support TLS 1.3${NC}"
        fi
    elif [[ -n "${choice_to_domain[$sni_choice]}" ]]; then
        new_sni="${choice_to_domain[$sni_choice]}"
    else
        # Invalid choice or empty, use default
        new_sni="$default_domain"
    fi
    
    echo -e "${GREEN}Selected SNI: ${MAGENTA}$new_sni${NC}"
    
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
    
    cp /etc/sing-box/config.json /etc/sing-box/config.json.bak.$(date +%Y%m%d_%H%M%S)
    
    echo -e "\n${BLUE}DNS Strategy Management${NC}"
    echo -e "${YELLOW}Select what you want to configure:${NC}"
    echo -e "  ${CYAN}1) Change global DNS strategy${NC}"
    echo -e "  ${CYAN}2) Change streaming services strategy (Netflix, Disney, etc.)${NC}"
    echo -e "  ${CYAN}3) Change AI services strategy (ChatGPT, etc.)${NC}"
    echo -e "  ${CYAN}4) Change Google services strategy${NC}"
    echo -e "  ${CYAN}5) Change China services strategy${NC}"
    echo -e "  ${CYAN}6) View current DNS strategies${NC}"
    
    read -p "$(echo -e "${YELLOW}Enter your choice [1-6]: ${NC}")" dns_choice
    
    case $dns_choice in
        1)
            echo -e "\n${YELLOW}Select global DNS strategy:${NC}"
            echo -e "  ${CYAN}1) ipv4_only - Force IPv4 only${NC}"
            echo -e "  ${CYAN}2) ipv6_only - Force IPv6 only${NC}"
            echo -e "  ${CYAN}3) prefer_ipv4 - Prefer IPv4 but allow IPv6${NC}"
            echo -e "  ${CYAN}4) prefer_ipv6 - Prefer IPv6 but allow IPv4${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-4]: ${NC}")" strategy_choice
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;; 2) new_strategy="ipv6_only" ;; 3) new_strategy="prefer_ipv4" ;; 4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid option.${NC}"; return 1 ;;
            esac
            jq ".dns.strategy = \"$new_strategy\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            jq ".route.default_domain_resolver.strategy = \"$new_strategy\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            echo -e "${GREEN}Global DNS strategy updated to: ${MAGENTA}$new_strategy${NC}"
            ;;
        2)
            echo -e "\n${YELLOW}Select streaming services DNS strategy:${NC}"
            echo -e "  ${CYAN}1) ipv4_only - Force IPv4 (may cause issues with some services)${NC}"
            echo -e "  ${CYAN}2) ipv6_only - Force IPv6 (current default for streaming)${NC}"
            echo -e "  ${CYAN}3) prefer_ipv4 - Prefer IPv4${NC}"
            echo -e "  ${CYAN}4) prefer_ipv6 - Prefer IPv6${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-4]: ${NC}")" strategy_choice
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;; 2) new_strategy="ipv6_only" ;; 3) new_strategy="prefer_ipv4" ;; 4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid option.${NC}"; return 1 ;;
            esac
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and (contains([\"geosite-netflix\"]) or contains([\"geosite-disney\"]) or contains([\"geosite-category-media\"]))) or (.rule_set | type == \"string\" and (. == \"geosite-netflix\" or . == \"geosite-disney\" or . == \"geosite-category-media\")) then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            echo -e "${GREEN}Streaming services DNS strategy updated to: ${MAGENTA}$new_strategy${NC}"
            ;;
        3) # AI Services
            echo -e "\n${YELLOW}Select AI services DNS strategy:${NC}"
            echo -e "  ${CYAN}1) ipv4_only - Force IPv4 (current default)${NC}"
            echo -e "  ${CYAN}2) ipv6_only - Force IPv6${NC}"
            echo -e "  ${CYAN}3) prefer_ipv4 - Prefer IPv4${NC}"
            echo -e "  ${CYAN}4) prefer_ipv6 - Prefer IPv6${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-4]: ${NC}")" strategy_choice
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;; 2) new_strategy="ipv6_only" ;; 3) new_strategy="prefer_ipv4" ;; 4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid option.${NC}"; return 1 ;;
            esac
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and contains([\"geosite-ai-chat-!cn\"])) or (.rule_set | type == \"string\" and . == \"geosite-ai-chat-!cn\") then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            echo -e "${GREEN}AI services DNS strategy updated to: ${MAGENTA}$new_strategy${NC}"
            ;;
        4) # Google Services
            echo -e "\n${YELLOW}Select Google services DNS strategy:${NC}"
            echo -e "  ${CYAN}1) ipv4_only - Force IPv4 (current default)${NC}"
            echo -e "  ${CYAN}2) ipv6_only - Force IPv6${NC}"
            echo -e "  ${CYAN}3) prefer_ipv4 - Prefer IPv4${NC}"
            echo -e "  ${CYAN}4) prefer_ipv6 - Prefer IPv6${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-4]: ${NC}")" strategy_choice
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;; 2) new_strategy="ipv6_only" ;; 3) new_strategy="prefer_ipv4" ;; 4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid option.${NC}"; return 1 ;;
            esac
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and contains([\"geosite-google\"])) or (.rule_set | type == \"string\" and . == \"geosite-google\") then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            echo -e "${GREEN}Google services DNS strategy updated to: ${MAGENTA}$new_strategy${NC}"
            ;;
        5) # China Services
            echo -e "\n${YELLOW}Select China services DNS strategy:${NC}"
            echo -e "  ${CYAN}1) ipv4_only - Force IPv4${NC}"
            echo -e "  ${CYAN}2) ipv6_only - Force IPv6${NC}"
            echo -e "  ${CYAN}3) prefer_ipv4 - Prefer IPv4 (current default)${NC}"
            echo -e "  ${CYAN}4) prefer_ipv6 - Prefer IPv6${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-4]: ${NC}")" strategy_choice
            case $strategy_choice in
                1) new_strategy="ipv4_only" ;; 2) new_strategy="ipv6_only" ;; 3) new_strategy="prefer_ipv4" ;; 4) new_strategy="prefer_ipv6" ;;
                *) echo -e "${RED}Invalid option.${NC}"; return 1 ;;
            esac
            jq ".dns.rules = [.dns.rules[] | if (.rule_set | type == \"array\" and (contains([\"geoip-cn\"]) or contains([\"geosite-cn\"]))) or (.rule_set | type == \"string\" and (. == \"geoip-cn\" or . == \"geosite-cn\")) then .strategy = \"$new_strategy\" else . end]" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            echo -e "${GREEN}China services DNS strategy updated to: ${MAGENTA}$new_strategy${NC}"
            ;;
        6)
            echo -e "\n${BLUE}Current DNS Strategies${NC}"
            echo -e "  ${CYAN}Global strategy: ${MAGENTA}$(jq -r '.dns.strategy' /etc/sing-box/config.json)${NC}"
            echo -e "\n  ${YELLOW}Service-specific strategies:${NC}"
            local streaming_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and contains(["geosite-netflix"])) or (.rule_set | type == "string" and . == "geosite-netflix")) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "    ${CYAN}Streaming (Netflix/Disney): ${MAGENTA}${streaming_strategy:-default}${NC}"
            local ai_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and contains(["geosite-ai-chat-!cn"])) or (.rule_set | type == "string" and . == "geosite-ai-chat-!cn")) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "    ${CYAN}AI services: ${MAGENTA}${ai_strategy:-default}${NC}"
            local google_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and contains(["geosite-google"])) or (.rule_set | type == "string" and . == "geosite-google")) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "    ${CYAN}Google services: ${MAGENTA}${google_strategy:-default}${NC}"
            local china_strategy=$(jq -r '.dns.rules[] | select((.rule_set | type == "array" and (contains(["geoip-cn"]) or contains(["geosite-cn"]))) or (.rule_set | type == "string" and (. == "geoip-cn" or . == "geosite-cn"))) | .strategy' /etc/sing-box/config.json | head -1)
            echo -e "    ${CYAN}China services: ${MAGENTA}${china_strategy:-default}${NC}"
            return 0
            ;;
        *)
            echo -e "${RED}Invalid option.${NC}"
            return 1
            ;;
    esac
    
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    if ! format_config; then echo -e "${RED}Error: Configuration validation failed.${NC}"; return 1; fi
    echo -e "${CYAN}Restarting Sing-Box service...${NC}"
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
    
    echo -e "\n${BLUE}Change DNS Servers${NC}"
    echo -e "${CYAN}Current DNS servers (first few):${NC}"
    jq -r '.dns.servers[:3][] | "  - \(.tag // \"N/A\"): \(.server // \"N/A\")"' /etc/sing-box/config.json | sed 's/^/  /' | sed 's/- /${CYAN}- /g; s/: /: ${MAGENTA}/g' # Colorize output
    
    echo -e "\n${YELLOW}Select DNS server to change or add:${NC}"
    echo -e "  ${CYAN}1) Change primary DNS (currently: ${MAGENTA}$(jq -r '.dns.servers[0].server' /etc/sing-box/config.json)${CYAN})${NC}"
    echo -e "  ${CYAN}2) Change secondary DNS (currently: ${MAGENTA}$(jq -r '.dns.servers[1].server' /etc/sing-box/config.json)${CYAN})${NC}"
    echo -e "  ${CYAN}3) Add custom DNS server${NC}"
    
    read -p "$(echo -e "${YELLOW}Enter your choice [1-3]: ${NC}")" dns_choice
    local new_server=""
    case $dns_choice in
        1|2)
            local server_index=$((dns_choice - 1))
            local server_desc="primary"
            if [[ $server_index -eq 1 ]]; then server_desc="secondary"; fi
            echo -e "\n${YELLOW}Select new $server_desc DNS:${NC}"
            echo -e "  ${CYAN}1) Cloudflare (1.1.1.1)${NC}"
            echo -e "  ${CYAN}2) Google (8.8.8.8)${NC}"
            echo -e "  ${CYAN}3) Quad9 (9.9.9.9)${NC}"
            echo -e "  ${CYAN}4) OpenDNS (208.67.222.222)${NC}"
            echo -e "  ${CYAN}5) Custom${NC}"
            read -p "$(echo -e "${YELLOW}Enter your choice [1-5]: ${NC}")" server_choice
            case $server_choice in
                1) new_server="1.1.1.1" ;; 2) new_server="8.8.8.8" ;; 3) new_server="9.9.9.9" ;; 4) new_server="208.67.222.222" ;;
                5) read -p "$(echo -e "${YELLOW}Enter custom DNS server IP: ${NC}")" new_server ;;
                *) echo -e "${RED}Invalid option.${NC}"; return 1 ;;
            esac
            if ! [[ "$new_server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ && $server_choice -eq 5 ]] && ! [[ $server_choice -ne 5 ]]; then 
                 if ! [[ "$new_server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then 
                    echo -e "${RED}Invalid IP address format for custom DNS.${NC}"; return 1;
                 fi
            fi
            jq ".dns.servers[$server_index].server = \"$new_server\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            echo -e "${GREEN}${server_desc^} DNS server updated to: ${MAGENTA}$new_server${NC}"
            ;;
        3)
            read -p "$(echo -e "${YELLOW}Enter custom DNS server IP: ${NC}")" new_server
            if ! [[ "$new_server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                echo -e "${RED}Invalid IP address format.${NC}"; return 1;
            fi
            read -p "$(echo -e "${YELLOW}Enter a tag name for this DNS server (e.g., custom_dns): ${NC}")" dns_tag
            if [[ -z "$dns_tag" ]]; then dns_tag="custom_dns_$(date +%s)"; fi 
            jq ".dns.servers += [{\"tag\": \"$dns_tag\", \"type\": \"https\", \"server\": \"$new_server\"}]" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            echo -e "${GREEN}Custom DNS server added: ${MAGENTA}$new_server${GREEN} (tag: ${MAGENTA}$dns_tag${GREEN})${NC}"
            ;;
        *)
            echo -e "${RED}Invalid option.${NC}"
            return 1
            ;;
    esac
    
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json
    if ! format_config; then echo -e "${RED}Error: Configuration validation failed.${NC}"; return 1; fi
    echo -e "${CYAN}Restarting Sing-Box service...${NC}"
    systemctl restart sing-box
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}DNS servers updated successfully!${NC}"
    else
        echo -e "${RED}Error: Service failed to restart.${NC}"
        return 1
    fi
}

# Function to configure streaming media unlock (类似 SNI Proxy + smartdns)
configure_streaming_unlock() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi

    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}流媒体解锁配置 (Streaming Media Unlock)${NC}       ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${CYAN}此功能类似 SNI Proxy + smartdns 方案，通过以下方式实现解锁:${NC}"
    echo -e "  ${GREEN}✓${NC} DNS 分流 - 不同流媒体使用不同 DNS 策略"
    echo -e "  ${GREEN}✓${NC} FakeIP 加速 - 减少 DNS 查询延迟"
    echo -e "  ${GREEN}✓${NC} IPv6 优先 - 提高解锁成功率"
    echo -e "  ${GREEN}✓${NC} 智能路由 - 自动选择最佳线路\n"

    echo -e "${YELLOW}选择配置模式:${NC}"
    echo -e "  ${CYAN}1)${NC} 启用 FakeIP 模式 (推荐 - 性能最佳)"
    echo -e "  ${CYAN}2)${NC} 标准 DNS 模式 (兼容性最佳)"
    echo -e "  ${CYAN}3)${NC} 查看当前配置"
    echo -e "  ${CYAN}0)${NC} 返回主菜单\n"

    read -p "$(echo -e "${YELLOW}请选择 [0-3]: ${NC}")" unlock_choice

    case $unlock_choice in
        1)
            echo -e "\n${BLUE}启用 FakeIP 模式${NC}"

            # 检查是否已有 FakeIP 服务器
            local has_fakeip=$(jq -e '.dns.servers[] | select(.type == "fakeip")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)

            if [[ $has_fakeip -ne 0 ]]; then
                echo -e "${CYAN}添加 FakeIP DNS 服务器...${NC}"
                jq '.dns.servers = [{
                    "tag": "dns_fakeip",
                    "type": "fakeip",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                }] + .dns.servers' /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
            fi

            # 更新 DNS 规则 - 流媒体使用 FakeIP
            echo -e "${CYAN}配置流媒体 DNS 规则...${NC}"
            jq '
                .dns.rules = [
                    {
                        "rule_set": ["geosite-category-ads-all"],
                        "action": "reject"
                    },
                    {
                        "rule_set": ["geosite-netflix", "geosite-disney", "geosite-category-media"],
                        "server": "dns_fakeip",
                        "query_type": ["A", "AAAA"]
                    }
                ] + (.dns.rules | map(select(.rule_set[0] != "geosite-netflix" and .rule_set[0] != "geosite-disney" and .rule_set[0] != "geosite-category-media" and .rule_set[0] != "geosite-category-ads-all")))
            ' /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json

            # 确保 experimental.cache_file.store_fakeip 启用
            echo -e "${CYAN}启用 FakeIP 缓存...${NC}"
            jq '.experimental.cache_file.store_fakeip = true' /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json

            echo -e "${GREEN}✓ FakeIP 模式已启用${NC}"
            echo -e "${CYAN}性能优势:${NC}"
            echo -e "  - 减少 DNS 查询延迟 50-200ms"
            echo -e "  - 提高分流准确性"
            echo -e "  - 降低 DNS 泄漏风险"
            ;;

        2)
            echo -e "\n${BLUE}配置标准 DNS 模式${NC}"

            # 移除 FakeIP 规则，使用标准 DNS
            echo -e "${CYAN}配置流媒体 DNS 策略...${NC}"

            # 确保流媒体使用 IPv6 优先策略
            jq '
                .dns.rules = [
                    {
                        "rule_set": ["geosite-category-ads-all"],
                        "action": "reject"
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
                    }
                ] + (.dns.rules | map(select(.rule_set[0] != "geosite-netflix" and .rule_set[0] != "geosite-disney" and .rule_set[0] != "geosite-category-media" and .rule_set[0] != "geosite-category-ads-all")))
            ' /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json

            echo -e "${GREEN}✓ 标准 DNS 模式已配置${NC}"
            echo -e "${CYAN}特点:${NC}"
            echo -e "  - 兼容性最佳"
            echo -e "  - IPv6 优先解锁"
            echo -e "  - 适合所有场景"
            ;;

        3)
            echo -e "\n${BLUE}当前流媒体解锁配置${NC}"
            echo -e "${CYAN}═══════════════════════════════════════${NC}\n"

            # 检查 FakeIP 配置
            local has_fakeip=$(jq -e '.dns.servers[] | select(.type == "fakeip")' /etc/sing-box/config.json >/dev/null 2>&1; echo $?)
            if [[ $has_fakeip -eq 0 ]]; then
                echo -e "${GREEN}✓ FakeIP 模式: 已启用${NC}"
                jq -r '.dns.servers[] | select(.type == "fakeip")' /etc/sing-box/config.json
            else
                echo -e "${YELLOW}○ FakeIP 模式: 未启用${NC}"
            fi

            echo -e "\n${CYAN}流媒体 DNS 规则:${NC}"
            jq -r '.dns.rules[] | select(.rule_set != null) | select(.rule_set[] | contains("netflix") or contains("disney") or contains("media"))' /etc/sing-box/config.json 2>/dev/null || echo -e "${YELLOW}未找到流媒体规则${NC}"

            echo -e "\n${CYAN}FakeIP 缓存状态:${NC}"
            local fakeip_cache=$(jq -r '.experimental.cache_file.store_fakeip // false' /etc/sing-box/config.json)
            if [[ "$fakeip_cache" == "true" ]]; then
                echo -e "${GREEN}✓ 已启用${NC}"
            else
                echo -e "${YELLOW}○ 未启用${NC}"
            fi

            return 0
            ;;

        0)
            return 0
            ;;

        *)
            echo -e "${RED}无效选项${NC}"
            return 1
            ;;
    esac

    # 应用配置
    chown sing-box:sing-box /etc/sing-box/config.json
    chmod 640 /etc/sing-box/config.json

    if ! format_config; then
        echo -e "${RED}Error: Configuration validation failed.${NC}"
        return 1
    fi

    echo -e "\n${CYAN}重启 Sing-Box 服务以应用更改...${NC}"
    systemctl restart sing-box

    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ 流媒体解锁配置已成功应用!${NC}\n"

        echo -e "${BLUE}使用建议:${NC}"
        echo -e "  ${CYAN}1.${NC} 确保服务器支持 IPv6"
        echo -e "  ${CYAN}2.${NC} 客户端需要启用 IPv6"
        echo -e "  ${CYAN}3.${NC} 测试流媒体访问: Netflix, Disney+, etc."
        echo -e "  ${CYAN}4.${NC} 如遇问题，可切换到标准 DNS 模式\n"
    else
        echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
        return 1
    fi
}

# Function to configure DNS routing (按平台配置不同 DNS)
configure_dns_routing() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}DNS 分流配置 (按平台配置不同 DNS)${NC}              ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${CYAN}此功能允许为不同的流媒体平台配置不同的 DNS 服务器${NC}"
    echo -e "${CYAN}例如: Netflix 使用 Cloudflare, Disney+ 使用 Google DNS${NC}\n"

    echo -e "${YELLOW}请选择操作:${NC}"
    echo -e "  ${CYAN}1)${NC} 配置 DNS 分流规则"
    echo -e "  ${CYAN}2)${NC} 查看当前 DNS 分流配置"
    echo -e "  ${CYAN}3)${NC} 恢复默认 DNS 配置"
    echo -e "  ${CYAN}0)${NC} 返回主菜单\n"

    read -p "请选择 [0-3]: " dns_routing_choice

    case $dns_routing_choice in
        1)
            configure_dns_routing_rules
            ;;
        2)
            view_dns_routing_config
            ;;
        3)
            restore_default_dns_config
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            ;;
    esac
}

# Function to configure custom DNS server
configure_custom_dns() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}配置自定义解锁 DNS 服务器${NC}                      ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}\n"

    # 输入 DNS 服务器地址
    while true; do
        read -p "请输入 DNS 服务器地址 (IP 或域名): " custom_dns_server

        # 验证输入不为空
        if [[ -z "$custom_dns_server" ]]; then
            echo -e "${RED}错误: DNS 服务器地址不能为空${NC}"
            continue
        fi

        # 简单验证 IP 地址或域名格式
        if [[ $custom_dns_server =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $custom_dns_server =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            break
        else
            echo -e "${RED}错误: 无效的 IP 地址或域名格式${NC}"
        fi
    done

    # 选择 DNS 协议类型
    echo -e "\n${YELLOW}选择 DNS 协议类型:${NC}"
    echo -e "  ${CYAN}1)${NC} UDP (传统 DNS, 端口 53)"
    echo -e "  ${CYAN}2)${NC} TCP (传统 DNS over TCP, 端口 53)"
    echo -e "  ${CYAN}3)${NC} DoH (DNS-over-HTTPS, 端口 443) ${GREEN}推荐${NC}"
    echo -e "  ${CYAN}4)${NC} DoT (DNS-over-TLS, 端口 853)"
    echo -e "  ${CYAN}5)${NC} DoQ (DNS-over-QUIC, 端口 853)"
    echo -e "  ${CYAN}6)${NC} DoH3 (DNS-over-HTTP/3, 端口 443)\n"

    read -p "请选择 [1-6, 默认: 3]: " dns_protocol
    dns_protocol=${dns_protocol:-3}

    case $dns_protocol in
        1)
            custom_dns_type="udp"
            custom_dns_port=53
            ;;
        2)
            custom_dns_type="tcp"
            custom_dns_port=53
            ;;
        3)
            custom_dns_type="https"
            custom_dns_port=443
            read -p "请输入 DoH 路径 [默认: /dns-query]: " custom_dns_path
            custom_dns_path=${custom_dns_path:-/dns-query}
            ;;
        4)
            custom_dns_type="tls"
            custom_dns_port=853
            ;;
        5)
            custom_dns_type="quic"
            custom_dns_port=853
            ;;
        6)
            custom_dns_type="http3"
            custom_dns_port=443
            read -p "请输入 DoH3 路径 [默认: /dns-query]: " custom_dns_path
            custom_dns_path=${custom_dns_path:-/dns-query}
            ;;
        *)
            custom_dns_type="https"
            custom_dns_port=443
            custom_dns_path="/dns-query"
            ;;
    esac

    # 自定义端口
    read -p "DNS 端口 [默认: $custom_dns_port]: " custom_port_input
    if [[ -n "$custom_port_input" ]]; then
        custom_dns_port=$custom_port_input
    fi

    # 自定义标签名称
    read -p "DNS 服务器标签名称 [默认: dns_custom_unlock]: " custom_dns_tag
    custom_dns_tag=${custom_dns_tag:-dns_custom_unlock}

    # 显示配置摘要
    echo -e "\n${CYAN}自定义 DNS 配置摘要:${NC}"
    echo -e "  标签: ${GREEN}$custom_dns_tag${NC}"
    echo -e "  类型: ${GREEN}$custom_dns_type${NC}"
    echo -e "  服务器: ${GREEN}$custom_dns_server${NC}"
    echo -e "  端口: ${GREEN}$custom_dns_port${NC}"
    if [[ -n "$custom_dns_path" ]]; then
        echo -e "  路径: ${GREEN}$custom_dns_path${NC}"
    fi

    read -p "确认配置? [Y/n]: " confirm
    confirm=${confirm:-Y}

    if [[ $confirm =~ ^[Yy]$ ]]; then
        custom_dns_configured=true
        echo -e "${GREEN}✓ 自定义 DNS 配置完成${NC}\n"
    else
        echo -e "${YELLOW}已取消自定义 DNS 配置${NC}\n"
        custom_dns_configured=false
    fi
}

# Function to configure DNS routing rules
configure_dns_routing_rules() {
    echo -e "\n${CYAN}配置 DNS 分流规则${NC}\n"

    # 检查配置文件
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}错误: 配置文件不存在${NC}"
        return 1
    fi

    # 显示可用的 DNS 服务器
    echo -e "${YELLOW}可用的 DNS 服务器:${NC}"
    echo -e "  ${CYAN}1)${NC} Cloudflare DNS (1.1.1.1) - 推荐用于流媒体解锁"
    echo -e "  ${CYAN}2)${NC} Google DNS (8.8.8.8) - 稳定性好"
    echo -e "  ${CYAN}3)${NC} AdGuard DNS (94.140.14.14) - 广告过滤"
    echo -e "  ${CYAN}4)${NC} Quad9 DNS (9.9.9.9) - 安全防护"
    echo -e "  ${CYAN}5)${NC} 本地 DNS (系统默认)"
    echo -e "  ${CYAN}6)${NC} 自定义解锁 DNS 服务器 ${YELLOW}(输入自己的 DNS)${NC}\n"

    # 初始化自定义 DNS 变量
    custom_dns_configured=false
    custom_dns_tag=""
    custom_dns_type=""
    custom_dns_server=""
    custom_dns_port=""
    custom_dns_path=""

    # 配置 Netflix
    echo -e "${YELLOW}[1/5] Netflix 使用哪个 DNS 服务器?${NC}"
    read -p "请选择 [1-6, 默认: 1]: " netflix_dns
    netflix_dns=${netflix_dns:-1}

    # 如果选择自定义 DNS，配置自定义 DNS 服务器
    if [[ $netflix_dns == 6 ]] && [[ $custom_dns_configured == false ]]; then
        configure_custom_dns
    fi

    # 配置 Disney+
    echo -e "${YELLOW}[2/5] Disney+ 使用哪个 DNS 服务器?${NC}"
    read -p "请选择 [1-6, 默认: 2]: " disney_dns
    disney_dns=${disney_dns:-2}

    if [[ $disney_dns == 6 ]] && [[ $custom_dns_configured == false ]]; then
        configure_custom_dns
    fi

    # 配置 Spotify
    echo -e "${YELLOW}[3/5] Spotify 使用哪个 DNS 服务器?${NC}"
    read -p "请选择 [1-6, 默认: 3]: " spotify_dns
    spotify_dns=${spotify_dns:-3}

    if [[ $spotify_dns == 6 ]] && [[ $custom_dns_configured == false ]]; then
        configure_custom_dns
    fi

    # 配置 YouTube
    echo -e "${YELLOW}[4/5] YouTube 使用哪个 DNS 服务器?${NC}"
    read -p "请选择 [1-6, 默认: 2]: " youtube_dns
    youtube_dns=${youtube_dns:-2}

    if [[ $youtube_dns == 6 ]] && [[ $custom_dns_configured == false ]]; then
        configure_custom_dns
    fi

    # 配置其他流媒体
    echo -e "${YELLOW}[5/5] 其他流媒体使用哪个 DNS 服务器?${NC}"
    read -p "请选择 [1-6, 默认: 1]: " other_dns
    other_dns=${other_dns:-1}

    if [[ $other_dns == 6 ]] && [[ $custom_dns_configured == false ]]; then
        configure_custom_dns
    fi

    # 配置解析策略
    echo -e "\n${YELLOW}选择解析策略:${NC}"
    echo -e "  ${CYAN}1)${NC} ipv4_only - 仅 IPv4"
    echo -e "  ${CYAN}2)${NC} ipv6_only - 仅 IPv6 (推荐用于流媒体解锁)"
    echo -e "  ${CYAN}3)${NC} prefer_ipv4 - 优先 IPv4"
    echo -e "  ${CYAN}4)${NC} prefer_ipv6 - 优先 IPv6\n"

    read -p "Netflix 解析策略 [1-4, 默认: 2]: " netflix_strategy
    netflix_strategy=${netflix_strategy:-2}

    read -p "Disney+ 解析策略 [1-4, 默认: 2]: " disney_strategy
    disney_strategy=${disney_strategy:-2}

    read -p "其他流媒体解析策略 [1-4, 默认: 4]: " other_strategy
    other_strategy=${other_strategy:-4}

    # 转换选择为实际值
    get_dns_server() {
        case $1 in
            1) echo "dns_cloudflare" ;;
            2) echo "dns_google" ;;
            3) echo "dns_adguard" ;;
            4) echo "dns_quad9" ;;
            5) echo "dns_local" ;;
            6) echo "$custom_dns_tag" ;;
            *) echo "dns_cloudflare" ;;
        esac
    }

    get_strategy() {
        case $1 in
            1) echo "ipv4_only" ;;
            2) echo "ipv6_only" ;;
            3) echo "prefer_ipv4" ;;
            4) echo "prefer_ipv6" ;;
            *) echo "prefer_ipv4" ;;
        esac
    }

    netflix_server=$(get_dns_server $netflix_dns)
    disney_server=$(get_dns_server $disney_dns)
    spotify_server=$(get_dns_server $spotify_dns)
    youtube_server=$(get_dns_server $youtube_dns)
    other_server=$(get_dns_server $other_dns)

    netflix_strat=$(get_strategy $netflix_strategy)
    disney_strat=$(get_strategy $disney_strategy)
    other_strat=$(get_strategy $other_strategy)

    echo -e "\n${CYAN}正在应用 DNS 分流配置...${NC}"

    # 备份当前配置
    cp /etc/sing-box/config.json /etc/sing-box/config.json.backup.$(date +%Y%m%d_%H%M%S)

    # 更新 DNS 配置
    # 首先确保所有预设 DNS 服务器都存在
    if [[ $custom_dns_configured == true ]]; then
        # 如果配置了自定义 DNS，添加到服务器列表
        if [[ "$custom_dns_type" == "https" ]] || [[ "$custom_dns_type" == "http3" ]]; then
            # DoH 或 DoH3 需要 path 参数
            jq --arg cf "dns_cloudflare" \
               --arg gg "dns_google" \
               --arg ag "dns_adguard" \
               --arg q9 "dns_quad9" \
               --arg local "dns_local" \
               --arg custom_tag "$custom_dns_tag" \
               --arg custom_type "$custom_dns_type" \
               --arg custom_server "$custom_dns_server" \
               --argjson custom_port "$custom_dns_port" \
               --arg custom_path "$custom_dns_path" \
               '.dns.servers = [
                   {
                       "tag": $cf,
                       "type": "https",
                       "server": "1.1.1.1",
                       "server_port": 443
                   },
                   {
                       "tag": $gg,
                       "type": "https",
                       "server": "8.8.8.8",
                       "server_port": 443
                   },
                   {
                       "tag": $ag,
                       "type": "https",
                       "server": "94.140.14.14",
                       "server_port": 443
                   },
                   {
                       "tag": $q9,
                       "type": "https",
                       "server": "9.9.9.9",
                       "server_port": 443
                   },
                   {
                       "tag": $local,
                       "type": "local"
                   },
                   {
                       "tag": $custom_tag,
                       "type": $custom_type,
                       "server": $custom_server,
                       "server_port": $custom_port,
                       "path": $custom_path
                   }
               ] + (.dns.servers | map(select(.tag == "dns_fakeip" or .tag == "dns_block")))' \
               /etc/sing-box/config.json > /tmp/config_temp.json && mv /tmp/config_temp.json /etc/sing-box/config.json
        else
            # UDP、TCP、DoT、DoQ 不需要 path 参数
            jq --arg cf "dns_cloudflare" \
               --arg gg "dns_google" \
               --arg ag "dns_adguard" \
               --arg q9 "dns_quad9" \
               --arg local "dns_local" \
               --arg custom_tag "$custom_dns_tag" \
               --arg custom_type "$custom_dns_type" \
               --arg custom_server "$custom_dns_server" \
               --argjson custom_port "$custom_dns_port" \
               '.dns.servers = [
                   {
                       "tag": $cf,
                       "type": "https",
                       "server": "1.1.1.1",
                       "server_port": 443
                   },
                   {
                       "tag": $gg,
                       "type": "https",
                       "server": "8.8.8.8",
                       "server_port": 443
                   },
                   {
                       "tag": $ag,
                       "type": "https",
                       "server": "94.140.14.14",
                       "server_port": 443
                   },
                   {
                       "tag": $q9,
                       "type": "https",
                       "server": "9.9.9.9",
                       "server_port": 443
                   },
                   {
                       "tag": $local,
                       "type": "local"
                   },
                   {
                       "tag": $custom_tag,
                       "type": $custom_type,
                       "server": $custom_server,
                       "server_port": $custom_port
                   }
               ] + (.dns.servers | map(select(.tag == "dns_fakeip" or .tag == "dns_block")))' \
               /etc/sing-box/config.json > /tmp/config_temp.json && mv /tmp/config_temp.json /etc/sing-box/config.json
        fi
    else
        # 没有自定义 DNS，使用原有配置
        jq --arg cf "dns_cloudflare" \
           --arg gg "dns_google" \
           --arg ag "dns_adguard" \
           --arg q9 "dns_quad9" \
           --arg local "dns_local" \
           '.dns.servers = [
               {
                   "tag": $cf,
                   "type": "https",
                   "server": "1.1.1.1",
                   "server_port": 443
               },
               {
                   "tag": $gg,
                   "type": "https",
                   "server": "8.8.8.8",
                   "server_port": 443
               },
               {
                   "tag": $ag,
                   "type": "https",
                   "server": "94.140.14.14",
                   "server_port": 443
               },
               {
                   "tag": $q9,
                   "type": "https",
                   "server": "9.9.9.9",
                   "server_port": 443
               },
               {
                   "tag": $local,
                   "type": "local"
               }
           ] + (.dns.servers | map(select(.tag == "dns_fakeip" or .tag == "dns_block")))' \
           /etc/sing-box/config.json > /tmp/config_temp.json && mv /tmp/config_temp.json /etc/sing-box/config.json
    fi

    # 更新 DNS 规则
    jq --arg netflix_srv "$netflix_server" \
       --arg disney_srv "$disney_server" \
       --arg spotify_srv "$spotify_server" \
       --arg youtube_srv "$youtube_server" \
       --arg other_srv "$other_server" \
       --arg netflix_st "$netflix_strat" \
       --arg disney_st "$disney_strat" \
       --arg other_st "$other_strat" \
       '.dns.rules = [
           (.dns.rules[] | select(.rule_set and (.rule_set | contains(["geosite-category-ads-all"])))),
           {
               "rule_set": ["geosite-netflix"],
               "server": $netflix_srv,
               "strategy": $netflix_st
           },
           {
               "rule_set": ["geosite-disney"],
               "server": $disney_srv,
               "strategy": $disney_st
           },
           {
               "rule_set": ["geosite-spotify"],
               "server": $spotify_srv,
               "strategy": "prefer_ipv4"
           },
           {
               "rule_set": ["geosite-youtube"],
               "server": $youtube_srv,
               "strategy": "prefer_ipv6"
           },
           {
               "rule_set": ["geosite-category-media"],
               "server": $other_srv,
               "strategy": $other_st
           }
       ] + (.dns.rules | map(select(.rule_set and (.rule_set | contains(["geoip-cn", "geosite-cn"])))))
       + [{"server": "dns_google", "strategy": "prefer_ipv4"}]' \
       /etc/sing-box/config.json > /tmp/config_temp.json && mv /tmp/config_temp.json /etc/sing-box/config.json

    echo -e "${GREEN}✓ DNS 分流配置已更新${NC}\n"

    # 显示配置摘要
    echo -e "${CYAN}配置摘要:${NC}"
    echo -e "  Netflix  → $netflix_server ($netflix_strat)"
    echo -e "  Disney+  → $disney_server ($disney_strat)"
    echo -e "  Spotify  → $spotify_server (prefer_ipv4)"
    echo -e "  YouTube  → $youtube_server (prefer_ipv6)"
    echo -e "  其他流媒体 → $other_server ($other_strat)"

    # 如果配置了自定义 DNS，显示详细信息
    if [[ $custom_dns_configured == true ]]; then
        echo -e "\n${YELLOW}自定义 DNS 服务器:${NC}"
        echo -e "  标签: ${GREEN}$custom_dns_tag${NC}"
        echo -e "  类型: ${GREEN}$custom_dns_type${NC}"
        echo -e "  服务器: ${GREEN}$custom_dns_server:$custom_dns_port${NC}"
        if [[ -n "$custom_dns_path" ]]; then
            echo -e "  路径: ${GREEN}$custom_dns_path${NC}"
        fi
    fi
    echo ""

    # 验证配置
    if sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1; then
        echo -e "${GREEN}✓ 配置验证通过${NC}"

        read -p "是否立即重启服务以应用配置? [Y/n]: " restart_confirm
        restart_confirm=${restart_confirm:-Y}

        if [[ $restart_confirm =~ ^[Yy]$ ]]; then
            systemctl restart sing-box
            if systemctl is-active --quiet sing-box; then
                echo -e "${GREEN}✓ 服务重启成功，DNS 分流配置已生效${NC}"
            else
                echo -e "${RED}✗ 服务重启失败，请检查日志${NC}"
                return 1
            fi
        fi
    else
        echo -e "${RED}✗ 配置验证失败${NC}"
        echo -e "${YELLOW}正在恢复备份...${NC}"
        cp /etc/sing-box/config.json.backup.$(date +%Y%m%d)* /etc/sing-box/config.json 2>/dev/null
        return 1
    fi
}

# Function to view DNS routing configuration
view_dns_routing_config() {
    echo -e "\n${CYAN}当前 DNS 分流配置${NC}\n"

    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}错误: 配置文件不存在${NC}"
        return 1
    fi

    echo -e "${YELLOW}DNS 服务器:${NC}"
    jq -r '.dns.servers[] | "  \(.tag): \(.type) - \(.server // "系统默认")"' /etc/sing-box/config.json

    echo -e "\n${YELLOW}DNS 分流规则:${NC}"
    jq -r '.dns.rules[] | select(.rule_set) | "  \(.rule_set | join(", ")) → \(.server) (\(.strategy // "默认"))"' /etc/sing-box/config.json
}

# Function to restore default DNS configuration
restore_default_dns_config() {
    echo -e "\n${YELLOW}确认要恢复默认 DNS 配置吗?${NC}"
    read -p "此操作将覆盖当前的 DNS 分流设置 [y/N]: " confirm

    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}已取消${NC}"
        return
    fi

    # 备份当前配置
    cp /etc/sing-box/config.json /etc/sing-box/config.json.backup.$(date +%Y%m%d_%H%M%S)

    # 恢复默认 DNS 配置
    jq '.dns.servers = [
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
            "tag": "dns_local",
            "type": "local"
        }
    ] + (.dns.servers | map(select(.tag == "dns_fakeip" or .tag == "dns_block")))' \
    /etc/sing-box/config.json > /tmp/config_temp.json && mv /tmp/config_temp.json /etc/sing-box/config.json

    echo -e "${GREEN}✓ 已恢复默认 DNS 配置${NC}"

    systemctl restart sing-box
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ 服务重启成功${NC}"
    else
        echo -e "${RED}✗ 服务重启失败${NC}"
    fi
}

# Function to configure DNS unlock server (纯 DNS 解锁服务器)
configure_dns_unlock_server() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}纯 DNS 解锁服务器配置 (不代理流量)${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${CYAN}此功能将 sing-box 配置为纯 DNS 解锁服务器${NC}"
    echo -e "${CYAN}只提供 DNS 解析服务，不代理流量${NC}"
    echo -e "${CYAN}客户端设置 DNS 为本服务器 IP 即可使用${NC}\n"

    echo -e "${YELLOW}请选择操作:${NC}"
    echo -e "  ${CYAN}1)${NC} 部署纯 DNS 解锁服务器"
    echo -e "  ${CYAN}2)${NC} 查看 DNS 服务器配置"
    echo -e "  ${CYAN}3)${NC} 测试 DNS 服务器"
    echo -e "  ${CYAN}4)${NC} 生成客户端配置说明"
    echo -e "  ${CYAN}0)${NC} 返回主菜单\n"

    read -p "请选择 [0-4]: " dns_server_choice

    case $dns_server_choice in
        1)
            deploy_dns_unlock_server
            ;;
        2)
            view_dns_server_config
            ;;
        3)
            test_dns_server
            ;;
        4)
            generate_client_dns_guide
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            ;;
    esac
}

# Function to deploy DNS unlock server
deploy_dns_unlock_server() {
    echo -e "\n${CYAN}部署纯 DNS 解锁服务器${NC}\n"

    # 检查是否已安装 sing-box
    if ! command -v sing-box &> /dev/null; then
        echo -e "${RED}错误: sing-box 未安装${NC}"
        echo -e "${YELLOW}请先运行主菜单选项 1 安装 sing-box${NC}"
        return 1
    fi

    # 配置监听地址
    echo -e "${YELLOW}DNS 服务器监听配置${NC}"
    read -p "监听地址 [默认: 0.0.0.0]: " listen_addr
    listen_addr=${listen_addr:-0.0.0.0}

    read -p "监听端口 [默认: 53]: " listen_port
    listen_port=${listen_port:-53}

    # 检测是否已有 DNS 解锁配置
    local has_unlock_dns=false
    local unlock_dns_server=""
    local use_detected_dns=false

    if [[ -f /etc/sing-box/config.json ]]; then
        # 检查是否有流媒体 DNS 规则配置
        if jq -e '.dns.rules[] | select(.rule_set and (.rule_set | contains(["geosite-netflix"])))' /etc/sing-box/config.json >/dev/null 2>&1; then
            has_unlock_dns=true
            # 获取 Netflix 使用的 DNS 服务器
            unlock_dns_server=$(jq -r '.dns.rules[] | select(.rule_set and (.rule_set | contains(["geosite-netflix"]))) | .server' /etc/sing-box/config.json 2>/dev/null | head -1)

            if [[ -n "$unlock_dns_server" && "$unlock_dns_server" != "null" ]]; then
                echo -e "\n${GREEN}✓ 检测到本机已配置的 DNS 解锁服务器: $unlock_dns_server${NC}"

                # 获取 DNS 服务器详细信息用于显示
                local dns_info=$(jq -r ".dns.servers[] | select(.tag == \"$unlock_dns_server\")" /etc/sing-box/config.json 2>/dev/null)
                if [[ -n "$dns_info" && "$dns_info" != "null" ]]; then
                    local dns_type=$(echo "$dns_info" | jq -r '.type')
                    local dns_server=$(echo "$dns_info" | jq -r '.server')
                    echo -e "${CYAN}  类型: $dns_type${NC}"
                    echo -e "${CYAN}  服务器: $dns_server${NC}"
                fi

                echo -e "\n${YELLOW}是否使用此解锁 DNS 作为上游（嵌套解锁）?${NC}"
                echo -e "${YELLOW}说明: 可以为其他服务器提供 DNS 解锁服务${NC}"
                echo -e "${RED}注意: 此行为可能违反某些服务商的 TOS${NC}"
                read -p "[Y/n]: " use_local_unlock
                use_local_unlock=${use_local_unlock:-Y}

                if [[ $use_local_unlock =~ ^[Yy]$ ]]; then
                    use_detected_dns=true
                fi
            fi
        fi
    fi

    # 如果用户不使用检测到的 DNS，或者没有检测到，询问是否手动输入
    local use_manual_unlock=false
    local manual_unlock_server=""
    local manual_unlock_type=""
    local manual_unlock_port=""
    local manual_unlock_path=""

    if [[ $use_detected_dns == false ]]; then
        echo -e "\n${YELLOW}是否使用其他服务器的解锁 DNS 作为上游（嵌套解锁）?${NC}"
        echo -e "${CYAN}例如: 使用另一台已配置解锁的服务器的 DNS${NC}"
        read -p "[y/N]: " use_other_unlock
        use_other_unlock=${use_other_unlock:-N}

        if [[ $use_other_unlock =~ ^[Yy]$ ]]; then
            echo -e "\n${CYAN}配置上游解锁 DNS 服务器${NC}"

            # 输入服务器地址
            while true; do
                read -p "请输入解锁 DNS 服务器地址 (IP 或域名): " manual_unlock_server

                if [[ -z "$manual_unlock_server" ]]; then
                    echo -e "${RED}错误: 服务器地址不能为空${NC}"
                    continue
                fi

                # 验证 IP 或域名格式
                if [[ $manual_unlock_server =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $manual_unlock_server =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                    break
                else
                    echo -e "${RED}错误: 无效的 IP 地址或域名格式${NC}"
                fi
            done

            # 选择协议类型
            echo -e "\n${YELLOW}选择 DNS 协议类型:${NC}"
            echo -e "  ${CYAN}1)${NC} UDP (传统 DNS, 端口 53)"
            echo -e "  ${CYAN}2)${NC} TCP (传统 DNS over TCP, 端口 53)"
            echo -e "  ${CYAN}3)${NC} DoH (DNS-over-HTTPS, 端口 443) ${GREEN}推荐${NC}"
            echo -e "  ${CYAN}4)${NC} DoT (DNS-over-TLS, 端口 853)"
            echo -e "  ${CYAN}5)${NC} DoQ (DNS-over-QUIC, 端口 853)"
            echo -e "  ${CYAN}6)${NC} DoH3 (DNS-over-HTTP/3, 端口 443)\n"

            read -p "请选择 [1-6, 默认: 3]: " dns_protocol
            dns_protocol=${dns_protocol:-3}

            case $dns_protocol in
                1)
                    manual_unlock_type="udp"
                    manual_unlock_port=53
                    ;;
                2)
                    manual_unlock_type="tcp"
                    manual_unlock_port=53
                    ;;
                3)
                    manual_unlock_type="https"
                    manual_unlock_port=443
                    read -p "请输入 DoH 路径 [默认: /dns-query]: " manual_unlock_path
                    manual_unlock_path=${manual_unlock_path:-/dns-query}
                    ;;
                4)
                    manual_unlock_type="tls"
                    manual_unlock_port=853
                    ;;
                5)
                    manual_unlock_type="quic"
                    manual_unlock_port=853
                    ;;
                6)
                    manual_unlock_type="http3"
                    manual_unlock_port=443
                    read -p "请输入 DoH3 路径 [默认: /dns-query]: " manual_unlock_path
                    manual_unlock_path=${manual_unlock_path:-/dns-query}
                    ;;
                *)
                    manual_unlock_type="https"
                    manual_unlock_port=443
                    manual_unlock_path="/dns-query"
                    ;;
            esac

            # 自定义端口
            read -p "DNS 端口 [默认: $manual_unlock_port]: " custom_port
            manual_unlock_port=${custom_port:-$manual_unlock_port}

            # 显示配置摘要
            echo -e "\n${CYAN}上游解锁 DNS 配置摘要:${NC}"
            echo -e "  服务器: ${GREEN}$manual_unlock_server${NC}"
            echo -e "  类型: ${GREEN}$manual_unlock_type${NC}"
            echo -e "  端口: ${GREEN}$manual_unlock_port${NC}"
            if [[ -n "$manual_unlock_path" ]]; then
                echo -e "  路径: ${GREEN}$manual_unlock_path${NC}"
            fi

            read -p "确认配置? [Y/n]: " confirm_manual
            confirm_manual=${confirm_manual:-Y}

            if [[ $confirm_manual =~ ^[Yy]$ ]]; then
                use_manual_unlock=true
                echo -e "${GREEN}✓ 上游解锁 DNS 配置完成${NC}"
            else
                echo -e "${YELLOW}已取消手动配置${NC}"
            fi
        fi
    fi

    # 选择上游 DNS 服务器
    echo -e "\n${YELLOW}选择公共上游 DNS 服务器 (可多选，用空格分隔)${NC}"

    if [[ $use_detected_dns == true ]] || [[ $use_manual_unlock == true ]]; then
        echo -e "${GREEN}已配置嵌套解锁，以下公共 DNS 将作为备用${NC}"
    fi

    echo -e "  ${CYAN}1)${NC} Cloudflare DNS (1.1.1.1)"
    echo -e "  ${CYAN}2)${NC} Google DNS (8.8.8.8)"
    echo -e "  ${CYAN}3)${NC} AdGuard DNS (94.140.14.14)"
    echo -e "  ${CYAN}4)${NC} Quad9 DNS (9.9.9.9)"
    echo -e "  ${CYAN}5)${NC} 全部公共 DNS"
    echo -e "  ${CYAN}0)${NC} 不使用公共 DNS（仅使用嵌套解锁）\n"

    read -p "请选择 [0-5, 默认: 1]: " upstream_choice
    upstream_choice=${upstream_choice:-1}

    # 是否启用广告拦截
    echo -e "\n${YELLOW}是否启用广告域名拦截?${NC}"
    read -p "[Y/n]: " enable_adblock
    enable_adblock=${enable_adblock:-Y}

    # 是否启用 FakeIP
    echo -e "\n${YELLOW}是否启用 FakeIP 加速?${NC}"
    echo -e "${CYAN}FakeIP 可以显著提升 DNS 解析速度${NC}"
    read -p "[Y/n]: " enable_fakeip
    enable_fakeip=${enable_fakeip:-Y}

    echo -e "\n${CYAN}正在生成 DNS 解锁服务器配置...${NC}"

    # 备份现有配置
    if [[ -f /etc/sing-box/config.json ]]; then
        cp /etc/sing-box/config.json /etc/sing-box/config.json.backup.dns.$(date +%Y%m%d_%H%M%S)
        echo -e "${GREEN}✓ 已备份现有配置${NC}"
    fi

    # 创建配置目录
    mkdir -p /etc/sing-box

    # 生成配置文件
    cat > /etc/sing-box/config.json << EOF
{
  "log": {
    "level": "info",
    "timestamp": true,
    "output": "/var/log/sing-box/dns-unlock.log"
  },
  "dns": {
    "servers": [
EOF

    # 首先添加真实的上游 DNS 服务器（FakeIP 不能作为第一个）
    local default_dns_added=false

    # 如果使用检测到的本机解锁 DNS
    if [[ $use_detected_dns == true ]] && [[ $has_unlock_dns == true ]]; then
        # 获取已配置的 DNS 服务器详细信息
        local unlock_dns_info=$(jq -r ".dns.servers[] | select(.tag == \"$unlock_dns_server\")" /etc/sing-box/config.json 2>/dev/null)

        if [[ -n "$unlock_dns_info" && "$unlock_dns_info" != "null" ]]; then
            local dns_type=$(echo "$unlock_dns_info" | jq -r '.type')
            local dns_server=$(echo "$unlock_dns_info" | jq -r '.server')
            local dns_port=$(echo "$unlock_dns_info" | jq -r '.server_port // empty')
            local dns_path=$(echo "$unlock_dns_info" | jq -r '.path // empty')

            cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_unlock_upstream",
        "type": "$dns_type",
        "server": "$dns_server"
EOF

            if [[ -n "$dns_port" ]]; then
                cat >> /etc/sing-box/config.json << EOF
,
        "server_port": $dns_port
EOF
            fi

            if [[ -n "$dns_path" ]]; then
                cat >> /etc/sing-box/config.json << EOF
,
        "path": "$dns_path"
EOF
            fi

            cat >> /etc/sing-box/config.json << EOF

      },
EOF
            default_dns_added=true
        fi
    fi

    # 如果使用手动输入的解锁 DNS
    if [[ $use_manual_unlock == true ]]; then
        cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_unlock_upstream",
        "type": "$manual_unlock_type",
        "server": "$manual_unlock_server",
        "server_port": $manual_unlock_port
EOF

        if [[ -n "$manual_unlock_path" ]]; then
            cat >> /etc/sing-box/config.json << EOF
,
        "path": "$manual_unlock_path"
EOF
        fi

        cat >> /etc/sing-box/config.json << EOF

      },
EOF
        default_dns_added=true
    fi

    # 添加公共 DNS 服务器（如果选择了）
    if [[ $upstream_choice != 0 ]]; then
        if [[ $upstream_choice == 5 ]] || [[ $upstream_choice =~ 1 ]]; then
            cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_cloudflare",
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443,
        "path": "/dns-query"
      },
EOF
            default_dns_added=true
        fi

        if [[ $upstream_choice == 5 ]] || [[ $upstream_choice =~ 2 ]]; then
            cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_google",
        "type": "https",
        "server": "8.8.8.8",
        "server_port": 443,
        "path": "/dns-query"
      },
EOF
            [[ $default_dns_added == false ]] && default_dns_added=true
        fi

        if [[ $upstream_choice == 5 ]] || [[ $upstream_choice =~ 3 ]]; then
            cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_adguard",
        "type": "https",
        "server": "94.140.14.14",
        "server_port": 443,
        "path": "/dns-query"
      },
EOF
            [[ $default_dns_added == false ]] && default_dns_added=true
        fi

        if [[ $upstream_choice == 5 ]] || [[ $upstream_choice =~ 4 ]]; then
            cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_quad9",
        "type": "https",
        "server": "9.9.9.9",
        "server_port": 443,
        "path": "/dns-query"
      },
EOF
            [[ $default_dns_added == false ]] && default_dns_added=true
        fi
    fi

    # 如果没有添加任何上游 DNS，添加 Cloudflare 作为默认
    if [[ $default_dns_added == false ]]; then
        cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_cloudflare",
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443,
        "path": "/dns-query"
      },
EOF
    fi

    # 现在添加 FakeIP 服务器（在真实 DNS 之后）
    if [[ $enable_fakeip =~ ^[Yy]$ ]]; then
        cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_fakeip",
        "type": "fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      },
EOF
    fi

    # 添加本地 DNS 和拦截 DNS
    cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "dns_local",
        "type": "local"
      },
      {
        "tag": "dns_block",
        "type": "hosts",
        "mapping": {}
      }
    ],
    "strategy": "prefer_ipv4",
    "independent_cache": true,
    "rules": [
EOF

    # 添加广告拦截规则
    if [[ $enable_adblock =~ ^[Yy]$ ]]; then
        cat >> /etc/sing-box/config.json << EOF
      {
        "rule_set": ["geosite-category-ads-all"],
        "action": "reject"
      },
EOF
    fi

    # 添加 FakeIP 规则
    if [[ $enable_fakeip =~ ^[Yy]$ ]]; then
        cat >> /etc/sing-box/config.json << EOF
      {
        "rule_set": ["geosite-netflix", "geosite-disney", "geosite-category-media"],
        "server": "dns_fakeip",
        "query_type": ["A", "AAAA"]
      },
EOF
    fi

    # 确定默认 DNS 服务器
    local default_server="dns_cloudflare"
    if [[ $use_detected_dns == true ]] || [[ $use_manual_unlock == true ]]; then
        default_server="dns_unlock_upstream"
    elif [[ $upstream_choice == 2 ]]; then
        default_server="dns_google"
    elif [[ $upstream_choice == 3 ]]; then
        default_server="dns_adguard"
    elif [[ $upstream_choice == 4 ]]; then
        default_server="dns_quad9"
    elif [[ $upstream_choice == 0 ]]; then
        # 仅使用嵌套解锁，没有公共 DNS
        default_server="dns_unlock_upstream"
    fi

    # 添加流媒体 DNS 规则
    cat >> /etc/sing-box/config.json << EOF
      {
        "rule_set": ["geosite-netflix"],
        "server": "$default_server",
        "strategy": "ipv6_only"
      },
      {
        "rule_set": ["geosite-disney"],
        "server": "$default_server",
        "strategy": "ipv6_only"
      },
      {
        "rule_set": ["geosite-spotify"],
        "server": "$default_server",
        "strategy": "prefer_ipv4"
      },
      {
        "rule_set": ["geosite-youtube"],
        "server": "$default_server",
        "strategy": "prefer_ipv6"
      },
      {
        "rule_set": ["geosite-category-media"],
        "server": "$default_server",
        "strategy": "ipv6_only"
      },
      {
        "rule_set": ["geoip-cn", "geosite-cn"],
        "server": "dns_local",
        "strategy": "prefer_ipv4"
      },
      {
        "server": "$default_server",
        "strategy": "prefer_ipv4"
      }
    ]
  },
  "services": [
    {
      "type": "resolved",
      "listen": "$listen_addr",
      "listen_port": $listen_port
    }
  ],
  "route": {
    "rule_set": [
EOF

    # 添加规则集
    if [[ $enable_adblock =~ ^[Yy]$ ]]; then
        cat >> /etc/sing-box/config.json << EOF
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads-all.srs",
        "download_detour": "direct"
      },
EOF
    fi

    cat >> /etc/sing-box/config.json << EOF
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
        "tag": "geosite-spotify",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/spotify.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs",
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
      }
    ],
    "auto_detect_interface": true,
    "final": "direct"
  },
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "/var/lib/sing-box/cache.db",
      "store_rdrc": true
EOF

    if [[ $enable_fakeip =~ ^[Yy]$ ]]; then
        cat >> /etc/sing-box/config.json << EOF
,
      "store_fakeip": true
EOF
    fi

    cat >> /etc/sing-box/config.json << EOF
    }
  }
}
EOF

    echo -e "${GREEN}✓ 配置文件已生成${NC}"

    # 显示配置摘要
    echo -e "\n${CYAN}配置摘要:${NC}"
    echo -e "  监听地址: ${GREEN}$listen_addr:$listen_port${NC}"

    # 显示上游 DNS 配置
    if [[ $use_detected_dns == true ]]; then
        echo -e "  上游 DNS: ${GREEN}本机解锁 DNS ($unlock_dns_server)${NC} ${YELLOW}[嵌套解锁]${NC}"
    elif [[ $use_manual_unlock == true ]]; then
        echo -e "  上游 DNS: ${GREEN}手动配置的解锁 DNS ($manual_unlock_server)${NC} ${YELLOW}[嵌套解锁]${NC}"
    fi

    # 显示公共 DNS 配置
    if [[ $upstream_choice == 0 ]]; then
        if [[ $use_detected_dns == true ]] || [[ $use_manual_unlock == true ]]; then
            echo -e "  公共 DNS: ${YELLOW}未配置（仅使用嵌套解锁）${NC}"
        else
            echo -e "  公共 DNS: ${GREEN}Cloudflare (默认)${NC}"
        fi
    elif [[ $upstream_choice == 5 ]]; then
        echo -e "  公共 DNS: ${GREEN}全部 (Cloudflare, Google, AdGuard, Quad9)${NC}"
    else
        local dns_names=""
        [[ $upstream_choice =~ 1 ]] && dns_names="Cloudflare"
        [[ $upstream_choice =~ 2 ]] && dns_names="${dns_names:+$dns_names, }Google"
        [[ $upstream_choice =~ 3 ]] && dns_names="${dns_names:+$dns_names, }AdGuard"
        [[ $upstream_choice =~ 4 ]] && dns_names="${dns_names:+$dns_names, }Quad9"
        echo -e "  公共 DNS: ${GREEN}$dns_names${NC}"
    fi

    echo -e "  FakeIP: $([ "$enable_fakeip" = "Y" ] && echo "${GREEN}已启用${NC}" || echo "${YELLOW}未启用${NC}")"
    echo -e "  广告拦截: $([ "$enable_adblock" = "Y" ] && echo "${GREEN}已启用${NC}" || echo "${YELLOW}未启用${NC}")"

    # 验证配置
    echo -e "\n${CYAN}验证配置文件...${NC}"
    if sing-box check -c /etc/sing-box/config.json 2>&1 | tee /tmp/sing-box-check.log; then
        echo -e "${GREEN}✓ 配置验证通过${NC}"
    else
        echo -e "${RED}✗ 配置验证失败${NC}"
        echo -e "\n${YELLOW}错误详情:${NC}"
        cat /tmp/sing-box-check.log
        echo -e "\n${YELLOW}提示:${NC}"
        echo -e "  - 如果提示 'default server cannot be fakeip'，说明 FakeIP 配置有问题"
        echo -e "  - 配置文件已保存到: /etc/sing-box/config.json"
        echo -e "  - 可以手动检查配置: ${CYAN}jq . /etc/sing-box/config.json${NC}"
        return 1
    fi

    # 创建日志目录
    mkdir -p /var/log/sing-box

    # 重启服务
    echo -e "\n${CYAN}重启 sing-box 服务...${NC}"
    systemctl restart sing-box

    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ DNS 解锁服务器部署成功！${NC}\n"

        # 显示服务器信息
        server_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "获取失败")

        echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}  ${YELLOW}DNS 解锁服务器信息${NC}                              ${BLUE}║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
        echo -e "${CYAN}服务器 IP:${NC} $server_ip"
        echo -e "${CYAN}DNS 端口:${NC} $listen_port"
        echo -e "${CYAN}监听地址:${NC} $listen_addr:$listen_port"

        # 显示上游 DNS 信息
        if [[ $use_detected_dns == true ]]; then
            echo -e "${CYAN}上游 DNS:${NC} 本机解锁 DNS ${YELLOW}(嵌套解锁)${NC}"
        elif [[ $use_manual_unlock == true ]]; then
            echo -e "${CYAN}上游 DNS:${NC} $manual_unlock_server ${YELLOW}(嵌套解锁)${NC}"
        fi

        # 显示公共 DNS 信息
        if [[ $upstream_choice == 0 ]]; then
            if [[ $use_detected_dns == false ]] && [[ $use_manual_unlock == false ]]; then
                echo -e "${CYAN}公共 DNS:${NC} Cloudflare (默认)"
            else
                echo -e "${CYAN}公共 DNS:${NC} 未配置"
            fi
        elif [[ $upstream_choice == 5 ]]; then
            echo -e "${CYAN}公共 DNS:${NC} 全部"
        else
            local dns_list=""
            [[ $upstream_choice =~ 1 ]] && dns_list="Cloudflare"
            [[ $upstream_choice =~ 2 ]] && dns_list="${dns_list:+$dns_list, }Google"
            [[ $upstream_choice =~ 3 ]] && dns_list="${dns_list:+$dns_list, }AdGuard"
            [[ $upstream_choice =~ 4 ]] && dns_list="${dns_list:+$dns_list, }Quad9"
            echo -e "${CYAN}公共 DNS:${NC} $dns_list"
        fi

        echo -e "${CYAN}FakeIP:${NC} $([ "$enable_fakeip" = "Y" ] && echo "已启用" || echo "未启用")"
        echo -e "${CYAN}广告拦截:${NC} $([ "$enable_adblock" = "Y" ] && echo "已启用" || echo "未启用")"
        echo -e "\n${YELLOW}客户端配置:${NC}"
        echo -e "  将设备的 DNS 设置为: ${GREEN}$server_ip${NC}"

        # 显示嵌套解锁说明
        if [[ $use_detected_dns == true ]] || [[ $use_manual_unlock == true ]]; then
            echo -e "\n${YELLOW}⚠ 嵌套解锁说明:${NC}"
            if [[ $use_detected_dns == true ]]; then
                echo -e "  此服务器使用本机已配置的解锁 DNS 作为上游"
            else
                echo -e "  此服务器使用 $manual_unlock_server 的解锁 DNS 作为上游"
            fi
            echo -e "  可以为其他服务器/客户端提供 DNS 解锁服务"
            echo -e "  ${RED}注意: 此行为可能违反某些服务商的 TOS${NC}"
        fi

        echo -e "\n${YELLOW}测试命令:${NC}"
        echo -e "  ${CYAN}nslookup netflix.com $server_ip${NC}"
        echo -e "  ${CYAN}dig @$server_ip netflix.com${NC}\n"

        # 检查防火墙
        if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
            echo -e "${YELLOW}⚠ 检测到 UFW 防火墙已启用${NC}"
            read -p "是否自动开放 DNS 端口 $listen_port? [Y/n]: " open_port
            open_port=${open_port:-Y}

            if [[ $open_port =~ ^[Yy]$ ]]; then
                ufw allow $listen_port/udp comment "sing-box DNS"
                ufw allow $listen_port/tcp comment "sing-box DNS"
                echo -e "${GREEN}✓ 已开放端口 $listen_port${NC}"
            fi
        fi

    else
        echo -e "${RED}✗ 服务启动失败${NC}"
        echo -e "${YELLOW}查看日志: journalctl -u sing-box -n 50${NC}"
        return 1
    fi
}

# Function to view DNS server configuration
view_dns_server_config() {
    echo -e "\n${CYAN}DNS 服务器配置${NC}\n"

    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}错误: 配置文件不存在${NC}"
        return 1
    fi

    # 检查是否为 DNS 服务器模式
    if ! jq -e '.services[] | select(.type == "resolved")' /etc/sing-box/config.json >/dev/null 2>&1; then
        echo -e "${YELLOW}当前配置不是纯 DNS 解锁服务器模式${NC}"
        return 1
    fi

    echo -e "${YELLOW}服务配置:${NC}"
    jq -r '.services[] | select(.type == "resolved") | "  监听地址: \(.listen):\(.listen_port)"' /etc/sing-box/config.json

    echo -e "\n${YELLOW}DNS 服务器:${NC}"
    jq -r '.dns.servers[] | "  \(.tag): \(.type) - \(.server // "系统默认")"' /etc/sing-box/config.json

    echo -e "\n${YELLOW}DNS 规则:${NC}"
    jq -r '.dns.rules[] |
        if .action then
            "  \(.rule_set | join(", ")) → \(.action)"
        elif .rule_set then
            "  \(.rule_set | join(", ")) → \(.server) (\(.strategy // "默认"))"
        else
            "  默认 → \(.server) (\(.strategy // "默认"))"
        end' /etc/sing-box/config.json
}

# Function to test DNS server
test_dns_server() {
    echo -e "\n${CYAN}测试 DNS 服务器${NC}\n"

    # 获取服务器 IP
    server_ip=$(curl -s https://api.ipify.org 2>/dev/null)
    if [[ -z "$server_ip" ]]; then
        read -p "无法自动获取服务器 IP，请手动输入: " server_ip
    fi

    # 获取 DNS 端口
    dns_port=$(jq -r '.services[] | select(.type == "resolved") | .listen_port' /etc/sing-box/config.json 2>/dev/null)
    dns_port=${dns_port:-53}

    echo -e "${YELLOW}测试服务器:${NC} $server_ip:$dns_port\n"

    # 检查必要工具
    if ! command -v dig &> /dev/null && ! command -v nslookup &> /dev/null; then
        echo -e "${RED}错误: 需要 dig 或 nslookup 工具${NC}"
        echo -e "${YELLOW}安装命令:${NC}"
        echo -e "  Ubuntu/Debian: ${CYAN}apt install dnsutils${NC}"
        echo -e "  CentOS/RHEL: ${CYAN}yum install bind-utils${NC}"
        return 1
    fi

    # 测试域名列表
    test_domains=("netflix.com" "disneyplus.com" "spotify.com" "youtube.com" "google.com")

    echo -e "${CYAN}开始测试...${NC}\n"

    for domain in "${test_domains[@]}"; do
        echo -e "${YELLOW}测试: $domain${NC}"

        if command -v dig &> /dev/null; then
            result=$(dig @$server_ip -p $dns_port $domain +short 2>/dev/null | head -n 3)
            if [[ -n "$result" ]]; then
                echo -e "${GREEN}✓ 解析成功:${NC}"
                echo "$result" | while read line; do
                    echo -e "  ${CYAN}$line${NC}"
                done
            else
                echo -e "${RED}✗ 解析失败${NC}"
            fi
        else
            nslookup $domain $server_ip 2>/dev/null | grep -A 2 "Name:" | tail -n 2
        fi
        echo ""
    done

    echo -e "${GREEN}测试完成${NC}"
}

# Function to generate client DNS configuration guide
generate_client_dns_guide() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}客户端 DNS 配置指南${NC}                            ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}\n"

    server_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
    dns_port=$(jq -r '.services[] | select(.type == "resolved") | .listen_port' /etc/sing-box/config.json 2>/dev/null)
    dns_port=${dns_port:-53}

    echo -e "${CYAN}DNS 服务器地址:${NC} ${GREEN}$server_ip${NC}"
    echo -e "${CYAN}DNS 端口:${NC} ${GREEN}$dns_port${NC}\n"

    echo -e "${YELLOW}═══ Windows 配置 ═══${NC}"
    echo -e "1. 打开 ${CYAN}控制面板 → 网络和 Internet → 网络连接${NC}"
    echo -e "2. 右键点击网络适配器 → ${CYAN}属性${NC}"
    echo -e "3. 选择 ${CYAN}Internet 协议版本 4 (TCP/IPv4)${NC} → ${CYAN}属性${NC}"
    echo -e "4. 选择 ${CYAN}使用下面的 DNS 服务器地址${NC}"
    echo -e "5. 首选 DNS 服务器: ${GREEN}$server_ip${NC}\n"

    echo -e "${YELLOW}═══ macOS 配置 ═══${NC}"
    echo -e "1. 打开 ${CYAN}系统偏好设置 → 网络${NC}"
    echo -e "2. 选择当前网络 → ${CYAN}高级${NC}"
    echo -e "3. 选择 ${CYAN}DNS${NC} 标签"
    echo -e "4. 点击 ${CYAN}+${NC} 添加 DNS 服务器: ${GREEN}$server_ip${NC}\n"

    echo -e "${YELLOW}═══ Linux 配置 ═══${NC}"
    echo -e "编辑 ${CYAN}/etc/resolv.conf${NC}:"
    echo -e "${GREEN}nameserver $server_ip${NC}\n"

    echo -e "${YELLOW}═══ iOS/iPadOS 配置 ═══${NC}"
    echo -e "1. 打开 ${CYAN}设置 → Wi-Fi${NC}"
    echo -e "2. 点击已连接网络的 ${CYAN}(i)${NC} 图标"
    echo -e "3. 选择 ${CYAN}配置 DNS → 手动${NC}"
    echo -e "4. 添加服务器: ${GREEN}$server_ip${NC}\n"

    echo -e "${YELLOW}═══ Android 配置 ═══${NC}"
    echo -e "1. 打开 ${CYAN}设置 → 网络和互联网 → Wi-Fi${NC}"
    echo -e "2. 长按已连接网络 → ${CYAN}修改网络${NC}"
    echo -e "3. ${CYAN}高级选项 → IP 设置 → 静态${NC}"
    echo -e "4. DNS 1: ${GREEN}$server_ip${NC}\n"

    echo -e "${YELLOW}═══ 路由器配置 (推荐) ═══${NC}"
    echo -e "在路由器管理界面设置 DHCP 的 DNS 服务器为: ${GREEN}$server_ip${NC}"
    echo -e "这样所有连接到路由器的设备都会自动使用 DNS 解锁\n"

    echo -e "${YELLOW}═══ 验证配置 ═══${NC}"
    echo -e "Windows: ${CYAN}nslookup netflix.com${NC}"
    echo -e "macOS/Linux: ${CYAN}dig netflix.com${NC}"
    echo -e "应该看到解析结果来自 ${GREEN}$server_ip${NC}\n"
}

# Function to view configuration
view_config() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}Current Configuration${NC}"
    cat /etc/sing-box/config.json | jq '.'
}

# Function to view service status
check_status() {
    echo -e "\n${BLUE}Sing-Box 服务状态${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    
    # 检查服务状态
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ 服务运行状态: 正在运行${NC}"
        
        # 获取运行时间
        local uptime=$(systemctl show sing-box --property=ActiveEnterTimestamp --value)
        if [[ -n "$uptime" ]]; then
            echo -e "${CYAN}启动时间: $uptime${NC}"
        fi
        
        # 获取内存使用
        local pid=$(systemctl show sing-box --property=MainPID --value)
        if [[ -n "$pid" ]] && [[ "$pid" != "0" ]]; then
            local mem_usage=$(ps -o rss= -p $pid 2>/dev/null | awk '{print $1/1024 " MB"}')
            if [[ -n "$mem_usage" ]]; then
                echo -e "${CYAN}内存使用: $mem_usage${NC}"
            fi
        fi
    else
        echo -e "${RED}✗ 服务运行状态: 未运行${NC}"
    fi
    
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    
    echo -e "\n${CYAN}详细信息:${NC}"
    systemctl status sing-box --no-pager
}

# Function to view logs
view_logs() {
    echo -e "\n${BLUE}Sing-Box 日志${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    
    echo -e "${CYAN}选择日志显示方式:${NC}"
    echo -e "  ${CYAN}1)${NC} 最近 50 行"
    echo -e "  ${CYAN}2)${NC} 最近 100 行"
    echo -e "  ${CYAN}3)${NC} 实时跟踪日志"
    echo -e "  ${CYAN}4)${NC} 查看错误日志"
    echo -ne "${YELLOW}请选择 [1-4] (默认: 1): ${NC}"
    
    read -r log_choice
    log_choice=${log_choice:-1}
    
    case "$log_choice" in
        1) journalctl -u sing-box -n 50 --no-pager ;;
        2) journalctl -u sing-box -n 100 --no-pager ;;
        3) 
            echo -e "${YELLOW}按 Ctrl+C 退出实时日志${NC}"
            journalctl -u sing-box -f
            ;;
        4) journalctl -u sing-box -p err -n 50 --no-pager ;;
        *) journalctl -u sing-box -n 50 --no-pager ;;
    esac
}

# Function to restart service
restart_service() {
    echo -e "\n${BLUE}重启 Sing-Box 服务${NC}"
    
    if confirm_action "确定要重启服务吗？"; then
        echo -e "${CYAN}正在停止服务...${NC}"
        systemctl stop sing-box
        sleep 1
        
        echo -e "${CYAN}正在启动服务...${NC}"
        systemctl start sing-box
        sleep 2
        
        if systemctl is-active --quiet sing-box; then
            log SUCCESS "服务重启成功"
            echo -e "${GREEN}✓ 服务重启成功！${NC}"
            
            # 显示服务状态
            echo -e "\n${CYAN}当前服务状态:${NC}"
            systemctl status sing-box --no-pager | head -10
        else
            log ERROR "服务重启失败"
            echo -e "${RED}✗ 服务重启失败${NC}"
            echo -e "${YELLOW}查看日志: journalctl -u sing-box -e${NC}"
        fi
    else
        echo -e "${YELLOW}已取消重启${NC}"
    fi
}

# Function to change Shadowsocks method
change_ss_method() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        echo -e "${RED}Error: Configuration file not found.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}Change Shadowsocks Encryption Method${NC}"
    
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
    jq "(.inbounds[] | select(.type == \"shadowsocks\") | .method) = \"$new_method\" | (.inbounds[] | select(.type == \"shadowsocks\") | .password) = \"$new_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
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
    echo -e "\n${BLUE}Change Shadowsocks Password Only${NC}"
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
    
    jq "(.inbounds[] | select(.type == \"shadowsocks\") | .password) = \"$shadowsocks_password\"" /etc/sing-box/config.json > /tmp/sing-box-temp.json && mv /tmp/sing-box-temp.json /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then echo -e "${RED}Shadowsocks password update failed.${NC}"; return 1; fi
        
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
    echo -e "${BLUE}╔═════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}Sing-Box & ShadowTLS ${SCRIPT_VERSION}${NC}  ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════════╝${NC}\n"
    
    # 主要操作
    echo -e "${GREEN} 主要操作${NC}"
    echo -e "  ${CYAN}1)${NC} 安装/更新 Sing-Box"
    echo -e "  ${CYAN}2)${NC} 卸载 Sing-Box"
    echo -e "  ${CYAN}3)${NC} 查看节点信息\n"
    
    # 服务管理
    echo -e "${GREEN} 服务管理${NC}"
    echo -e "  ${CYAN}4)${NC} 服务状态"
    echo -e "  ${CYAN}5)${NC} 查看日志"
    echo -e "  ${CYAN}6)${NC} 重启服务\n"
    
    # 配置管理
    echo -e "${GREEN} 配置管理${NC}"
    echo -e "  ${CYAN}7)${NC} 查看当前配置"
    echo -e "  ${CYAN}8)${NC} 端口设置"
    echo -e "  ${CYAN}9)${NC} 密码设置"
    echo -e "  ${CYAN}10)${NC} ShadowTLS 设置"
    echo -e "  ${CYAN}11)${NC} Shadowsocks 设置"
    echo -e "  ${CYAN}12)${NC} DNS 设置"
    echo -e "  ${CYAN}13)${NC} 流媒体解锁设置 ${YELLOW}(类似 SNI Proxy + smartdns)${NC}"
    echo -e "  ${CYAN}14)${NC} DNS 分流配置 ${YELLOW}(按平台配置不同 DNS)${NC}"
    echo -e "  ${CYAN}15)${NC} 纯 DNS 解锁服务器 ${YELLOW}(不代理流量)${NC}\n"

    # 系统工具
    echo -e "${GREEN} 系统工具${NC}"
    echo -e "  ${CYAN}16)${NC} 健康检查"
    echo -e "  ${CYAN}17)${NC} 系统优化"
    echo -e "  ${CYAN}18)${NC} 备份配置"
    echo -e "  ${CYAN}19)${NC} 恢复配置\n"

    echo -e "  ${CYAN}0)${NC} 退出\n"
    echo -ne "${YELLOW}请选择 [0-19]: ${NC}"
}

# Function to display port submenu
show_port_menu() {
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
            13)
                configure_streaming_unlock
                ;;
            14)
                configure_dns_routing
                ;;
            15)
                configure_dns_unlock_server
                ;;
            16)
                health_check
                ;;
            17)
                optimize_system
                ;;
            18)
                backup_config
                ;;
            19)
                restore_config
                ;;
            0)
                echo -e "${GREEN}退出中...${NC}"
                log INFO "脚本正常退出"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请重试${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}按 Enter 键继续...${NC}"
        read
    done
}

# Run main function
main "$@"
