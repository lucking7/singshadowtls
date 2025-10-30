#!/bin/bash

#############################################
# SNI Proxy 自动化安装和配置脚本
# 功能: 自动安装 SNI Proxy 并从 MetaCubeX 规则库提取域名
# 作者: Auto-generated
# 版本: 1.0.0
#############################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="/tmp/sniproxy_install_$$"
BACKUP_DIR="/etc/sniproxy_backup_$(date +%Y%m%d_%H%M%S)"
SNIPROXY_CONF="/etc/sniproxy.conf"
LOG_FILE="/var/log/sniproxy_install.log"

# 规则库 URL 映射
declare -A RULE_URLS=(
    ["Netflix"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.json"
    ["Disney+"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/disney.json"
    ["OpenAI"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.json"
    ["AI服务"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.json"
    ["Amazon Prime"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/primevideo.json"
    ["YouTube"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.json"
    ["HBO"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/hbo.json"
    ["Hulu"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/hulu.json"
)

# 日志函数
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 检测操作系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
    else
        log_error "无法检测操作系统类型"
        exit 1
    fi
    
    log_info "检测到操作系统: $OS $OS_VERSION"
}

# 检查网络连接
check_network() {
    log_info "检查网络连接..."
    
    if ! curl -s --connect-timeout 5 https://raw.githubusercontent.com > /dev/null 2>&1; then
        log_error "无法连接到 GitHub,请检查网络连接"
        echo "提示: 如果在中国大陆,可能需要配置代理"
        read -p "是否继续? (y/n): " continue_choice
        if [[ ! $continue_choice =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log "网络连接正常"
    fi
}

# 安装依赖
install_dependencies() {
    log_info "安装依赖包..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y build-essential autotools-dev cdbs debhelper \
                dh-autoreconf dpkg-dev gettext libev-dev libpcre3-dev \
                libudns-dev pkg-config fakeroot devscripts git curl jq
            ;;
        centos|rhel|fedora)
            yum groupinstall -y "Development Tools"
            yum install -y autoconf automake curl gettext-devel libev-devel \
                pcre-devel udns-devel git jq
            ;;
        *)
            log_error "不支持的操作系统: $OS"
            exit 1
            ;;
    esac
    
    log "依赖包安装完成"
}

# 编译安装 SNI Proxy
install_sniproxy() {
    log_info "开始编译安装 SNI Proxy..."
    
    cd "$TEMP_DIR"
    
    # 克隆源码
    if [[ ! -d "sniproxy" ]]; then
        log_info "克隆 SNI Proxy 源码..."
        git clone https://github.com/dlundquist/sniproxy.git
    fi
    
    cd sniproxy
    
    # 编译安装
    log_info "配置编译环境..."
    ./autogen.sh
    ./configure
    
    log_info "编译中..."
    make
    
    log_info "安装中..."
    make install
    
    log "SNI Proxy 编译安装完成"
}

# 创建 systemd 服务文件
create_systemd_service() {
    log_info "创建 systemd 服务文件..."
    
    cat > /etc/systemd/system/sniproxy.service << 'EOF'
[Unit]
Description=SNI Proxy
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sniproxy.pid
ExecStart=/usr/local/bin/sniproxy -c /etc/sniproxy.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log "systemd 服务文件创建完成"
}

# 从 JSON 提取域名
extract_domains_from_json() {
    local json_file=$1
    local domains=()
    
    # 提取 domain 字段
    if jq -e '.rules[].domain[]' "$json_file" > /dev/null 2>&1; then
        while IFS= read -r domain; do
            domains+=("$domain")
        done < <(jq -r '.rules[].domain[]?' "$json_file" 2>/dev/null | grep -v "^null$" || true)
    fi
    
    # 提取 domain_suffix 字段
    if jq -e '.rules[].domain_suffix[]' "$json_file" > /dev/null 2>&1; then
        while IFS= read -r suffix; do
            domains+=("$suffix")
        done < <(jq -r '.rules[].domain_suffix[]?' "$json_file" 2>/dev/null | grep -v "^null$" || true)
    fi
    
    # 输出去重后的域名
    printf '%s\n' "${domains[@]}" | sort -u
}

# 转换域名为 SNI Proxy 格式
convert_to_sniproxy_format() {
    local domain=$1
    
    # 移除前导点号
    domain="${domain#.}"
    
    # 转义点号
    domain="${domain//./\\.}"
    
    # 添加通配符和结尾
    echo "    .*${domain}\$ *"
}

# 下载并处理规则
download_and_process_rules() {
    local service_name=$1
    local url=$2
    local output_file="$TEMP_DIR/${service_name// /_}.json"
    
    log_info "下载 $service_name 规则..."
    
    if curl -fsSL "$url" -o "$output_file"; then
        # 验证 JSON 格式
        if ! jq empty "$output_file" 2>/dev/null; then
            log_warn "$service_name 规则文件格式无效,跳过"
            return 1
        fi
        
        local domain_count=$(extract_domains_from_json "$output_file" | wc -l)
        log "  ✓ $service_name: 提取到 $domain_count 个域名"
        return 0
    else
        log_warn "下载 $service_name 规则失败,跳过"
        return 1
    fi
}

# 显示服务选择菜单
show_service_menu() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  请选择需要解锁的服务 (可多选)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    local i=1
    local services=()
    
    for service in "${!RULE_URLS[@]}"; do
        services+=("$service")
        echo "  [$i] $service"
        ((i++))
    done
    
    echo "  [A] 全部选择"
    echo "  [0] 完成选择"
    echo ""
    
    # 返回服务列表
    printf '%s\n' "${services[@]}"
}

# 用户选择服务
select_services() {
    local -a services
    mapfile -t services < <(show_service_menu)

    local -a selected_services=()

    while true; do
        echo -n "请输入选项 (多个选项用空格分隔): "
        read -r choices

        if [[ "$choices" =~ [Aa] ]]; then
            selected_services=("${services[@]}")
            log_info "已选择全部服务"
            break
        elif [[ "$choices" =~ 0 ]]; then
            if [[ ${#selected_services[@]} -eq 0 ]]; then
                log_warn "至少选择一个服务"
                continue
            fi
            break
        fi

        for choice in $choices; do
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#services[@]} ]]; then
                local service="${services[$((choice-1))]}"
                if [[ ! " ${selected_services[@]} " =~ " ${service} " ]]; then
                    selected_services+=("$service")
                    log_info "已添加: $service"
                fi
            else
                log_warn "无效选项: $choice"
            fi
        done
    done

    echo ""
    log "已选择 ${#selected_services[@]} 个服务:"
    for service in "${selected_services[@]}"; do
        echo "  - $service"
    done
    echo ""

    printf '%s\n' "${selected_services[@]}"
}

# 生成 SNI Proxy 配置文件
generate_sniproxy_config() {
    local -a selected_services=("$@")

    log_info "生成 SNI Proxy 配置文件..."

    # 备份原有配置
    if [[ -f "$SNIPROXY_CONF" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp "$SNIPROXY_CONF" "$BACKUP_DIR/sniproxy.conf"
        log_info "原配置已备份到: $BACKUP_DIR"
    fi

    # 创建配置文件头部
    cat > "$SNIPROXY_CONF" << 'EOF'
user daemon
pidfile /var/run/sniproxy.pid

error_log {
    syslog daemon
    priority notice
}

resolver {
    nameserver 8.8.8.8
    nameserver 8.8.4.4
    nameserver 1.1.1.1
    mode ipv4_only
}

listener 0.0.0.0:80 {
    proto http
    access_log {
        filename /var/log/sniproxy/http_access.log
        priority notice
    }
}

listener 0.0.0.0:443 {
    proto tls
    access_log {
        filename /var/log/sniproxy/https_access.log
        priority notice
    }
}

table {
EOF

    # 处理每个选中的服务
    local total_domains=0

    for service in "${selected_services[@]}"; do
        local url="${RULE_URLS[$service]}"
        local json_file="$TEMP_DIR/${service// /_}.json"

        if [[ -f "$json_file" ]]; then
            echo "" >> "$SNIPROXY_CONF"
            echo "    # $service" >> "$SNIPROXY_CONF"

            local count=0
            while IFS= read -r domain; do
                convert_to_sniproxy_format "$domain" >> "$SNIPROXY_CONF"
                ((count++))
                ((total_domains++))
            done < <(extract_domains_from_json "$json_file")

            log_info "  ✓ $service: 添加了 $count 个域名规则"
        fi
    done

    # 添加配置文件尾部
    echo "}" >> "$SNIPROXY_CONF"

    log "配置文件生成完成,共添加 $total_domains 个域名规则"
}

# 创建日志目录
create_log_directory() {
    log_info "创建日志目录..."
    mkdir -p /var/log/sniproxy
    chmod 755 /var/log/sniproxy
    log "日志目录创建完成"
}

# 配置防火墙
configure_firewall() {
    log_info "检测防火墙配置..."

    if ! command -v ufw &> /dev/null; then
        log_warn "未检测到 UFW 防火墙"
        read -p "是否安装 UFW? (y/n): " install_ufw
        if [[ $install_ufw =~ ^[Yy]$ ]]; then
            case $OS in
                ubuntu|debian)
                    apt-get install -y ufw
                    ;;
                centos|rhel|fedora)
                    yum install -y ufw
                    ;;
            esac
        else
            log_info "跳过防火墙配置"
            return
        fi
    fi

    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  防火墙配置${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    echo "SNI Proxy 需要开放以下端口:"
    echo "  - 80/tcp  (HTTP)"
    echo "  - 443/tcp (HTTPS)"
    echo ""
    echo "建议配置白名单,仅允许被解锁机访问"
    echo ""

    read -p "是否配置防火墙规则? (y/n): " config_fw

    if [[ $config_fw =~ ^[Yy]$ ]]; then
        echo ""
        echo "选择配置方式:"
        echo "  [1] 允许所有IP访问 (不推荐,有安全风险)"
        echo "  [2] 仅允许指定IP访问 (推荐)"
        echo ""
        read -p "请选择 (1/2): " fw_choice

        case $fw_choice in
            1)
                ufw allow 80/tcp
                ufw allow 443/tcp
                log "已允许所有IP访问 80 和 443 端口"
                ;;
            2)
                read -p "请输入被解锁机的IP地址: " client_ip
                if [[ -n "$client_ip" ]]; then
                    ufw allow from "$client_ip" to any port 80 proto tcp
                    ufw allow from "$client_ip" to any port 443 proto tcp
                    log "已允许 $client_ip 访问 80 和 443 端口"
                else
                    log_warn "未输入IP地址,跳过防火墙配置"
                fi
                ;;
            *)
                log_warn "无效选择,跳过防火墙配置"
                ;;
        esac

        # 确保 UFW 启用
        if ! ufw status | grep -q "Status: active"; then
            read -p "UFW 未启用,是否启用? (y/n): " enable_ufw
            if [[ $enable_ufw =~ ^[Yy]$ ]]; then
                # 确保 SSH 端口开放
                ufw allow 22/tcp
                echo "y" | ufw enable
                log "UFW 防火墙已启用"
            fi
        fi
    fi
}

# 启动 SNI Proxy
start_sniproxy() {
    log_info "启动 SNI Proxy..."

    # 测试配置文件
    if /usr/local/bin/sniproxy -t -c "$SNIPROXY_CONF"; then
        log "配置文件验证通过"
    else
        log_error "配置文件验证失败"
        exit 1
    fi

    # 启动服务
    systemctl enable sniproxy
    systemctl restart sniproxy

    # 检查状态
    sleep 2
    if systemctl is-active --quiet sniproxy; then
        log "SNI Proxy 启动成功"
    else
        log_error "SNI Proxy 启动失败"
        systemctl status sniproxy
        exit 1
    fi
}

# 显示配置摘要
show_summary() {
    local -a selected_services=("$@")

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  安装完成!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}配置摘要:${NC}"
    echo "  配置文件: $SNIPROXY_CONF"
    echo "  日志目录: /var/log/sniproxy/"
    echo "  备份目录: $BACKUP_DIR"
    echo ""
    echo -e "${BLUE}已启用的服务:${NC}"
    for service in "${selected_services[@]}"; do
        echo "  ✓ $service"
    done
    echo ""
    echo -e "${BLUE}服务状态:${NC}"
    systemctl status sniproxy --no-pager | head -n 10
    echo ""
    echo -e "${BLUE}监听端口:${NC}"
    ss -tlnp | grep sniproxy || netstat -tlnp | grep sniproxy
    echo ""
    echo -e "${YELLOW}重要提示:${NC}"
    echo "  1. 请确保防火墙已正确配置"
    echo "  2. 被解锁机需要配置 sing-box 指向本机IP"
    echo "  3. 查看日志: journalctl -u sniproxy -f"
    echo "  4. 重启服务: systemctl restart sniproxy"
    echo "  5. 查看配置: cat $SNIPROXY_CONF"
    echo ""

    # 获取本机IP
    local server_ip=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "无法获取")
    echo -e "${GREEN}本机公网IP: $server_ip${NC}"
    echo ""
    echo "在被解锁机的 sing-box 配置中,将域名解析到: $server_ip"
    echo ""
}

# 测试功能
test_sniproxy() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  测试 SNI Proxy${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    log_info "测试配置文件语法..."
    if /usr/local/bin/sniproxy -t -c "$SNIPROXY_CONF"; then
        log "✓ 配置文件语法正确"
    else
        log_error "✗ 配置文件语法错误"
        return 1
    fi

    log_info "测试服务状态..."
    if systemctl is-active --quiet sniproxy; then
        log "✓ 服务运行正常"
    else
        log_error "✗ 服务未运行"
        return 1
    fi

    log_info "测试端口监听..."
    if ss -tlnp | grep -q ":80 " && ss -tlnp | grep -q ":443 "; then
        log "✓ 端口 80 和 443 正在监听"
    else
        log_warn "✗ 端口监听异常"
        ss -tlnp | grep sniproxy
    fi

    echo ""
    log "测试完成"
}

# 清理临时文件
cleanup() {
    log_info "清理临时文件..."
    rm -rf "$TEMP_DIR"
    log "清理完成"
}

# 错误处理和回滚
rollback() {
    log_error "安装过程中出现错误,正在回滚..."

    if [[ -d "$BACKUP_DIR" ]] && [[ -f "$BACKUP_DIR/sniproxy.conf" ]]; then
        cp "$BACKUP_DIR/sniproxy.conf" "$SNIPROXY_CONF"
        log_info "已恢复原配置文件"
    fi

    systemctl stop sniproxy 2>/dev/null || true

    cleanup

    log_error "安装失败,已回滚"
    exit 1
}

# 主函数
main() {
    # 设置错误处理
    trap rollback ERR

    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║        SNI Proxy 自动化安装和配置脚本                  ║
║                                                       ║
║  功能: 自动安装 SNI Proxy 并配置流媒体解锁规则         ║
║  版本: 1.0.0                                          ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    # 检查 root 权限
    check_root

    # 创建临时目录
    mkdir -p "$TEMP_DIR"

    # 检测操作系统
    detect_os

    # 检查网络连接
    check_network

    # 询问是否继续
    echo ""
    read -p "是否继续安装? (y/n): " continue_install
    if [[ ! $continue_install =~ ^[Yy]$ ]]; then
        log_info "用户取消安装"
        exit 0
    fi

    # 安装依赖
    install_dependencies

    # 安装 SNI Proxy
    install_sniproxy

    # 创建 systemd 服务
    create_systemd_service

    # 创建日志目录
    create_log_directory

    # 用户选择服务
    echo ""
    local -a selected_services
    mapfile -t selected_services < <(select_services)

    # 下载规则
    echo ""
    log_info "开始下载规则文件..."
    for service in "${selected_services[@]}"; do
        download_and_process_rules "$service" "${RULE_URLS[$service]}"
    done

    # 生成配置文件
    echo ""
    generate_sniproxy_config "${selected_services[@]}"

    # 配置防火墙
    echo ""
    configure_firewall

    # 启动服务
    echo ""
    start_sniproxy

    # 测试
    test_sniproxy

    # 显示摘要
    show_summary "${selected_services[@]}"

    # 清理临时文件
    cleanup

    log "安装完成!"
}

# 运行主函数
main "$@"

