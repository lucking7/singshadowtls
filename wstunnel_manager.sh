#!/bin/bash

# wstunnel管理脚本 - TCP/UDP转发工具
# 支持IPv4/IPv6, 显示IP信息和ASN/ORG
# 适用于Ubuntu/Debian系统

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置文件路径
CONFIG_DIR="/etc/wstunnel"
CONFIG_FILE="$CONFIG_DIR/config.json"
LOG_DIR="/var/log/wstunnel"
WSTUNNEL_BIN="/usr/local/bin/wstunnel"

# 创建必要的目录
init_dirs() {
    sudo mkdir -p "$CONFIG_DIR" "$LOG_DIR"
}

# 检查是否以root权限运行
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${RED}请不要使用root权限运行此脚本！${NC}"
        echo -e "${YELLOW}某些功能需要sudo权限时会自动请求${NC}"
        exit 1
    fi
}

# 检查系统是否为Ubuntu/Debian
check_system() {
    if ! grep -E "debian|ubuntu" /etc/os-release > /dev/null 2>&1; then
        echo -e "${RED}此脚本仅支持Ubuntu/Debian系统！${NC}"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${YELLOW}正在安装依赖...${NC}"
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y curl jq wget dnsutils net-tools iproute2 > /dev/null 2>&1
    echo -e "${GREEN}依赖安装完成！${NC}"
}

# 获取本机IP信息
get_ip_info() {
    echo -e "${CYAN}========== 本机IP信息 ==========${NC}"
    
    # 获取IPv4地址
    echo -e "${YELLOW}IPv4地址:${NC}"
    local ipv4_addrs=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1')
    if [[ -n "$ipv4_addrs" ]]; then
        echo "$ipv4_addrs" | while read -r ip; do
            echo "  - $ip"
        done
    else
        echo "  - 无IPv4地址"
    fi
    
    # 获取IPv6地址
    echo -e "${YELLOW}IPv6地址:${NC}"
    local ipv6_addrs=$(ip -6 addr show | grep -oP '(?<=inet6\s)[0-9a-fA-F:]+' | grep -v '::1' | grep -v '^fe80')
    if [[ -n "$ipv6_addrs" ]]; then
        echo "$ipv6_addrs" | while read -r ip; do
            echo "  - $ip"
        done
    else
        echo "  - 无IPv6地址"
    fi
    
    # 获取公网IP和ASN信息
    echo -e "${YELLOW}公网IP信息:${NC}"
    local public_ip_info=$(curl -s https://ipinfo.io)
    if [[ -n "$public_ip_info" ]]; then
        local public_ip=$(echo "$public_ip_info" | jq -r '.ip')
        local org=$(echo "$public_ip_info" | jq -r '.org')
        local country=$(echo "$public_ip_info" | jq -r '.country')
        local city=$(echo "$public_ip_info" | jq -r '.city')
        
        echo "  - IP: $public_ip"
        echo "  - ASN/ORG: $org"
        echo "  - 位置: $city, $country"
    else
        echo "  - 无法获取公网IP信息"
    fi
    
    echo -e "${CYAN}================================${NC}"
}

# 检查wstunnel是否已安装
check_wstunnel() {
    if [[ -f "$WSTUNNEL_BIN" ]]; then
        local version=$("$WSTUNNEL_BIN" --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "${GREEN}wstunnel已安装 (版本: $version)${NC}"
        return 0
    else
        echo -e "${RED}wstunnel未安装${NC}"
        return 1
    fi
}

# 安装wstunnel
install_wstunnel() {
    echo -e "${YELLOW}正在下载wstunnel...${NC}"
    
    # 检测系统架构
    local arch=$(uname -m)
    local download_arch=""
    
    case $arch in
        x86_64)
            download_arch="x86_64"
            ;;
        aarch64)
            download_arch="aarch64"
            ;;
        armv7l)
            download_arch="armv7"
            ;;
        *)
            echo -e "${RED}不支持的架构: $arch${NC}"
            return 1
            ;;
    esac
    
    # 获取最新版本
    local latest_version=$(curl -s https://api.github.com/repos/erebe/wstunnel/releases/latest | jq -r '.tag_name')
    if [[ -z "$latest_version" ]]; then
        echo -e "${RED}无法获取最新版本信息${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}下载版本: $latest_version${NC}"
    
    # 下载对应架构的二进制文件
    local download_url="https://github.com/erebe/wstunnel/releases/download/${latest_version}/wstunnel_${latest_version:1}_linux_${download_arch}.tar.gz"
    
    cd /tmp
    if wget -q "$download_url" -O wstunnel.tar.gz; then
        tar -xzf wstunnel.tar.gz
        sudo mv wstunnel "$WSTUNNEL_BIN"
        sudo chmod +x "$WSTUNNEL_BIN"
        rm -f wstunnel.tar.gz
        echo -e "${GREEN}wstunnel安装成功！${NC}"
        return 0
    else
        echo -e "${RED}下载失败！${NC}"
        return 1
    fi
}

# 创建systemd服务
create_systemd_service() {
    local service_name=$1
    local service_type=$2  # client 或 server
    local service_config=$3
    
    cat << EOF | sudo tee "/etc/systemd/system/wstunnel-${service_name}.service" > /dev/null
[Unit]
Description=wstunnel $service_type - $service_name
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=$WSTUNNEL_BIN $service_config
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/${service_name}.log
StandardError=append:$LOG_DIR/${service_name}.log

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
}

# 保存配置
save_config() {
    local name=$1
    local type=$2
    local config=$3
    
    # 读取现有配置
    local configs="{}"
    if [[ -f "$CONFIG_FILE" ]]; then
        configs=$(cat "$CONFIG_FILE")
    fi
    
    # 添加新配置
    configs=$(echo "$configs" | jq --arg name "$name" --arg type "$type" --arg config "$config" \
        '.[$name] = {"type": $type, "config": $config, "created": now | strftime("%Y-%m-%d %H:%M:%S")}')
    
    # 保存配置
    echo "$configs" | sudo tee "$CONFIG_FILE" > /dev/null
}

# 列出所有配置
list_configs() {
    if [[ ! -f "$CONFIG_FILE" ]] || [[ $(cat "$CONFIG_FILE") == "{}" ]]; then
        echo -e "${YELLOW}暂无配置${NC}"
        return
    fi
    
    echo -e "${CYAN}========== 配置列表 ==========${NC}"
    jq -r 'to_entries[] | "\(.key) - \(.value.type) - \(.value.created)"' "$CONFIG_FILE"
    echo -e "${CYAN}==============================${NC}"
}

# 配置客户端
configure_client() {
    echo -e "${CYAN}========== 配置客户端 ==========${NC}"
    
    # 输入配置名称
    read -p "配置名称: " config_name
    if [[ -z "$config_name" ]]; then
        echo -e "${RED}配置名称不能为空！${NC}"
        return 1
    fi
    
    # 选择监听地址类型
    echo -e "${YELLOW}选择监听地址类型:${NC}"
    echo "1) IPv4 (127.0.0.1)"
    echo "2) IPv6 ([::1])"
    echo "3) 所有IPv4 (0.0.0.0)"
    echo "4) 所有IPv6 ([::])"
    echo "5) 自定义"
    read -p "请选择 [1-5]: " addr_choice
    
    local bind_addr=""
    case $addr_choice in
        1) bind_addr="127.0.0.1" ;;
        2) bind_addr="[::1]" ;;
        3) bind_addr="0.0.0.0" ;;
        4) bind_addr="[::]" ;;
        5) 
            read -p "输入监听地址: " bind_addr
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac
    
    # 选择隧道类型
    echo -e "${YELLOW}选择隧道类型:${NC}"
    echo "1) TCP端口转发"
    echo "2) UDP端口转发"
    echo "3) SOCKS5代理"
    echo "4) HTTP代理"
    echo "5) 透明代理(需要root权限)"
    read -p "请选择 [1-5]: " tunnel_type
    
    # 配置隧道参数
    local local_spec=""
    case $tunnel_type in
        1) # TCP转发
            read -p "本地端口: " local_port
            read -p "远程主机: " remote_host
            read -p "远程端口: " remote_port
            local_spec="tcp://${bind_addr}:${local_port}:${remote_host}:${remote_port}"
            ;;
        2) # UDP转发
            read -p "本地端口: " local_port
            read -p "远程主机: " remote_host
            read -p "远程端口: " remote_port
            read -p "超时时间(秒,0为禁用) [30]: " timeout
            timeout=${timeout:-30}
            local_spec="udp://${bind_addr}:${local_port}:${remote_host}:${remote_port}?timeout_sec=${timeout}"
            ;;
        3) # SOCKS5代理
            read -p "本地端口: " local_port
            local_spec="socks5://${bind_addr}:${local_port}"
            ;;
        4) # HTTP代理
            read -p "本地端口: " local_port
            local_spec="http://${bind_addr}:${local_port}"
            ;;
        5) # 透明代理
            echo -e "${YELLOW}选择透明代理协议:${NC}"
            echo "1) TCP"
            echo "2) UDP"
            read -p "请选择 [1-2]: " tproxy_proto
            read -p "本地端口: " local_port
            if [[ $tproxy_proto == "1" ]]; then
                local_spec="tproxy+tcp://${bind_addr}:${local_port}"
            else
                local_spec="tproxy+udp://${bind_addr}:${local_port}"
            fi
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac
    
    # 输入服务器地址
    read -p "wstunnel服务器地址 (如 wss://server.com:443): " server_addr
    
    # 高级选项
    echo -e "${YELLOW}是否配置高级选项? (y/n) [n]: ${NC}"
    read -p "" advanced
    
    local extra_opts=""
    if [[ "$advanced" == "y" ]]; then
        read -p "连接池大小 [0]: " pool_size
        pool_size=${pool_size:-0}
        if [[ $pool_size -gt 0 ]]; then
            extra_opts="$extra_opts --connection-min-idle $pool_size"
        fi
        
        read -p "HTTP代理 (留空跳过): " http_proxy
        if [[ -n "$http_proxy" ]]; then
            extra_opts="$extra_opts -p $http_proxy"
        fi
        
        read -p "自定义SNI域名 (留空跳过): " sni_override
        if [[ -n "$sni_override" ]]; then
            extra_opts="$extra_opts --tls-sni-override $sni_override"
        fi
    fi
    
    # 生成完整命令
    local full_command="client -L '$local_spec' $extra_opts '$server_addr'"
    
    # 保存配置
    save_config "$config_name" "client" "$full_command"
    
    # 创建systemd服务
    create_systemd_service "$config_name" "client" "$full_command"
    
    echo -e "${GREEN}客户端配置完成！${NC}"
    echo -e "${YELLOW}启动服务: sudo systemctl start wstunnel-${config_name}${NC}"
    echo -e "${YELLOW}开机自启: sudo systemctl enable wstunnel-${config_name}${NC}"
}

# 配置服务器
configure_server() {
    echo -e "${CYAN}========== 配置服务器 ==========${NC}"
    
    # 输入配置名称
    read -p "配置名称: " config_name
    if [[ -z "$config_name" ]]; then
        echo -e "${RED}配置名称不能为空！${NC}"
        return 1
    fi
    
    # 选择监听地址类型
    echo -e "${YELLOW}选择监听地址类型:${NC}"
    echo "1) 所有接口 IPv4 (0.0.0.0)"
    echo "2) 所有接口 IPv6 ([::])"
    echo "3) 仅本地 IPv4 (127.0.0.1)"
    echo "4) 仅本地 IPv6 ([::1])"
    echo "5) 自定义"
    read -p "请选择 [1-5]: " addr_choice
    
    local bind_addr=""
    case $addr_choice in
        1) bind_addr="0.0.0.0" ;;
        2) bind_addr="[::]" ;;
        3) bind_addr="127.0.0.1" ;;
        4) bind_addr="[::1]" ;;
        5) 
            read -p "输入监听地址: " bind_addr
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac
    
    # 输入端口
    read -p "监听端口 [8080]: " port
    port=${port:-8080}
    
    # 选择协议
    echo -e "${YELLOW}选择协议:${NC}"
    echo "1) WebSocket (ws://)"
    echo "2) WebSocket Secure (wss://)"
    read -p "请选择 [1-2]: " proto_choice
    
    local protocol=""
    local extra_opts=""
    
    case $proto_choice in
        1) protocol="ws" ;;
        2) 
            protocol="wss"
            echo -e "${YELLOW}TLS证书配置:${NC}"
            echo "1) 使用内置自签名证书"
            echo "2) 使用自定义证书"
            read -p "请选择 [1-2]: " cert_choice
            
            if [[ $cert_choice == "2" ]]; then
                read -p "证书文件路径: " cert_path
                read -p "私钥文件路径: " key_path
                if [[ -f "$cert_path" && -f "$key_path" ]]; then
                    extra_opts="$extra_opts --tls-certificate '$cert_path' --tls-private-key '$key_path'"
                else
                    echo -e "${RED}证书或私钥文件不存在！${NC}"
                    return 1
                fi
            fi
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac
    
    # 高级选项
    echo -e "${YELLOW}是否配置高级选项? (y/n) [n]: ${NC}"
    read -p "" advanced
    
    if [[ "$advanced" == "y" ]]; then
        # 访问控制
        echo -e "${YELLOW}是否限制可访问的目标? (y/n) [n]: ${NC}"
        read -p "" restrict
        if [[ "$restrict" == "y" ]]; then
            echo "输入允许访问的目标(格式: host:port)，每行一个，输入空行结束:"
            while true; do
                read -p "> " target
                if [[ -z "$target" ]]; then
                    break
                fi
                extra_opts="$extra_opts --restrict-to '$target'"
            done
        fi
        
        # 路径前缀限制
        read -p "HTTP升级路径前缀(用作密钥) [留空不限制]: " path_prefix
        if [[ -n "$path_prefix" ]]; then
            extra_opts="$extra_opts --restrict-http-upgrade-path-prefix '$path_prefix'"
        fi
    fi
    
    # 生成完整命令
    local server_addr="${protocol}://${bind_addr}:${port}"
    local full_command="server $extra_opts '$server_addr'"
    
    # 保存配置
    save_config "$config_name" "server" "$full_command"
    
    # 创建systemd服务
    create_systemd_service "$config_name" "server" "$full_command"
    
    echo -e "${GREEN}服务器配置完成！${NC}"
    echo -e "${YELLOW}服务器地址: ${server_addr}${NC}"
    echo -e "${YELLOW}启动服务: sudo systemctl start wstunnel-${config_name}${NC}"
    echo -e "${YELLOW}开机自启: sudo systemctl enable wstunnel-${config_name}${NC}"
}

# 管理服务
manage_services() {
    if [[ ! -f "$CONFIG_FILE" ]] || [[ $(cat "$CONFIG_FILE") == "{}" ]]; then
        echo -e "${YELLOW}暂无配置${NC}"
        return
    fi
    
    echo -e "${CYAN}========== 服务管理 ==========${NC}"
    
    # 列出所有服务及其状态
    jq -r 'keys[]' "$CONFIG_FILE" | while read -r name; do
        local status=$(systemctl is-active "wstunnel-${name}" 2>/dev/null || echo "未安装")
        local enabled=$(systemctl is-enabled "wstunnel-${name}" 2>/dev/null || echo "未安装")
        
        case $status in
            active)
                status_color="${GREEN}运行中${NC}"
                ;;
            inactive)
                status_color="${RED}已停止${NC}"
                ;;
            *)
                status_color="${YELLOW}${status}${NC}"
                ;;
        esac
        
        echo -e "$name - 状态: $status_color - 自启: $enabled"
    done
    
    echo ""
    read -p "输入要管理的服务名称 (留空返回): " service_name
    
    if [[ -z "$service_name" ]]; then
        return
    fi
    
    if ! jq -e --arg name "$service_name" '.[$name]' "$CONFIG_FILE" > /dev/null; then
        echo -e "${RED}服务不存在！${NC}"
        return
    fi
    
    echo -e "${YELLOW}选择操作:${NC}"
    echo "1) 启动"
    echo "2) 停止"
    echo "3) 重启"
    echo "4) 查看状态"
    echo "5) 查看日志"
    echo "6) 启用开机自启"
    echo "7) 禁用开机自启"
    echo "8) 删除配置"
    read -p "请选择 [1-8]: " action
    
    case $action in
        1)
            sudo systemctl start "wstunnel-${service_name}"
            echo -e "${GREEN}服务已启动${NC}"
            ;;
        2)
            sudo systemctl stop "wstunnel-${service_name}"
            echo -e "${GREEN}服务已停止${NC}"
            ;;
        3)
            sudo systemctl restart "wstunnel-${service_name}"
            echo -e "${GREEN}服务已重启${NC}"
            ;;
        4)
            sudo systemctl status "wstunnel-${service_name}"
            ;;
        5)
            echo -e "${CYAN}========== 最近日志 ==========${NC}"
            sudo tail -n 50 "$LOG_DIR/${service_name}.log" 2>/dev/null || echo "暂无日志"
            ;;
        6)
            sudo systemctl enable "wstunnel-${service_name}"
            echo -e "${GREEN}已启用开机自启${NC}"
            ;;
        7)
            sudo systemctl disable "wstunnel-${service_name}"
            echo -e "${GREEN}已禁用开机自启${NC}"
            ;;
        8)
            echo -e "${RED}确认删除配置 '$service_name'? (y/n): ${NC}"
            read -p "" confirm
            if [[ "$confirm" == "y" ]]; then
                sudo systemctl stop "wstunnel-${service_name}" 2>/dev/null
                sudo systemctl disable "wstunnel-${service_name}" 2>/dev/null
                sudo rm -f "/etc/systemd/system/wstunnel-${service_name}.service"
                sudo systemctl daemon-reload
                
                # 从配置文件中删除
                local new_config=$(jq --arg name "$service_name" 'del(.[$name])' "$CONFIG_FILE")
                echo "$new_config" | sudo tee "$CONFIG_FILE" > /dev/null
                
                echo -e "${GREEN}配置已删除${NC}"
            fi
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# 显示使用示例
show_examples() {
    echo -e "${CYAN}========== 使用示例 ==========${NC}"
    echo ""
    echo -e "${YELLOW}1. TCP端口转发示例:${NC}"
    echo "   本地端口 8080 转发到 google.com:443"
    echo "   客户端: wstunnel client -L tcp://127.0.0.1:8080:google.com:443 wss://server.com:443"
    echo ""
    echo -e "${YELLOW}2. UDP端口转发示例:${NC}"
    echo "   本地端口 53 转发到 8.8.8.8:53 (DNS)"
    echo "   客户端: wstunnel client -L udp://127.0.0.1:53:8.8.8.8:53 wss://server.com:443"
    echo ""
    echo -e "${YELLOW}3. SOCKS5代理示例:${NC}"
    echo "   在本地8888端口创建SOCKS5代理"
    echo "   客户端: wstunnel client -L socks5://127.0.0.1:8888 wss://server.com:443"
    echo ""
    echo -e "${YELLOW}4. 反向隧道示例:${NC}"
    echo "   将本地的8000端口暴露到服务器的9000端口"
    echo "   客户端: wstunnel client -R tcp://0.0.0.0:9000:localhost:8000 wss://server.com:443"
    echo ""
    echo -e "${YELLOW}5. 透明代理示例 (需要root):${NC}"
    echo "   创建透明代理，配合iptables使用"
    echo "   客户端: sudo wstunnel client -L tproxy+tcp://127.0.0.1:1080 wss://server.com:443"
    echo ""
    echo -e "${CYAN}==============================${NC}"
}

# 主菜单
main_menu() {
    while true; do
        clear
        echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║      wstunnel 管理工具 v1.0          ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
        echo ""
        
        # 显示wstunnel状态
        if check_wstunnel > /dev/null 2>&1; then
            local version=$("$WSTUNNEL_BIN" --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
            echo -e "wstunnel状态: ${GREEN}已安装 (v$version)${NC}"
        else
            echo -e "wstunnel状态: ${RED}未安装${NC}"
        fi
        echo ""
        
        echo -e "${YELLOW}主菜单:${NC}"
        echo "1) 显示本机IP信息"
        echo "2) 安装/更新 wstunnel"
        echo "3) 配置客户端"
        echo "4) 配置服务器"
        echo "5) 管理服务"
        echo "6) 查看所有配置"
        echo "7) 使用示例"
        echo "8) 退出"
        echo ""
        read -p "请选择 [1-8]: " choice
        
        case $choice in
            1)
                clear
                get_ip_info
                echo ""
                read -p "按回车键继续..."
                ;;
            2)
                clear
                if check_wstunnel > /dev/null 2>&1; then
                    echo -e "${YELLOW}是否要重新安装/更新 wstunnel? (y/n): ${NC}"
                    read -p "" update
                    if [[ "$update" == "y" ]]; then
                        install_wstunnel
                    fi
                else
                    install_wstunnel
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            3)
                clear
                if ! check_wstunnel > /dev/null 2>&1; then
                    echo -e "${RED}请先安装 wstunnel！${NC}"
                    read -p "按回车键继续..."
                    continue
                fi
                configure_client
                echo ""
                read -p "按回车键继续..."
                ;;
            4)
                clear
                if ! check_wstunnel > /dev/null 2>&1; then
                    echo -e "${RED}请先安装 wstunnel！${NC}"
                    read -p "按回车键继续..."
                    continue
                fi
                configure_server
                echo ""
                read -p "按回车键继续..."
                ;;
            5)
                clear
                manage_services
                echo ""
                read -p "按回车键继续..."
                ;;
            6)
                clear
                list_configs
                echo ""
                read -p "按回车键继续..."
                ;;
            7)
                clear
                show_examples
                echo ""
                read -p "按回车键继续..."
                ;;
            8)
                echo -e "${GREEN}再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择！${NC}"
                sleep 1
                ;;
        esac
    done
}

# 主程序
main() {
    check_root
    check_system
    init_dirs
    
    # 检查并安装依赖
    if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null; then
        install_dependencies
    fi
    
    main_menu
}

# 运行主程序
main "$@"