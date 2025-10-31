#!/bin/bash

#############################################
# sing-box DNS 解锁配置生成脚本
# 功能: 为被解锁机生成 sing-box 配置文件
# 配合 SNI Proxy 使用
# 版本: 1.0.0
#############################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 全局变量
TEMP_DIR="/tmp/singbox_config_$$"
OUTPUT_FILE="singbox_unlock_config.json"

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
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 从 JSON 提取域名后缀
extract_domain_suffixes() {
    local json_file=$1
    local suffixes=()
    
    # 提取 domain 字段
    if jq -e '.rules[].domain[]' "$json_file" > /dev/null 2>&1; then
        while IFS= read -r domain; do
            suffixes+=("$domain")
        done < <(jq -r '.rules[].domain[]?' "$json_file" 2>/dev/null | grep -v "^null$" || true)
    fi
    
    # 提取 domain_suffix 字段
    if jq -e '.rules[].domain_suffix[]' "$json_file" > /dev/null 2>&1; then
        while IFS= read -r suffix; do
            # 移除前导点号
            suffix="${suffix#.}"
            suffixes+=("$suffix")
        done < <(jq -r '.rules[].domain_suffix[]?' "$json_file" 2>/dev/null | grep -v "^null$" || true)
    fi
    
    # 输出去重后的域名
    printf '%s\n' "${suffixes[@]}" | sort -u
}

# 下载规则文件
download_rules() {
    local service_name=$1
    local url=$2
    local output_file="$TEMP_DIR/${service_name// /_}.json"
    
    log "下载 $service_name 规则..."
    
    if curl -fsSL "$url" -o "$output_file"; then
        if jq empty "$output_file" 2>/dev/null; then
            echo "$output_file"
            return 0
        else
            log_warn "$service_name 规则文件格式无效"
            return 1
        fi
    else
        log_warn "下载 $service_name 规则失败"
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
    for service in "${!RULE_URLS[@]}"; do
        echo "  [$i] $service"
        ((i++))
    done
    
    echo "  [A] 全部选择"
    echo "  [0] 完成选择"
    echo ""
}

# 用户选择服务
select_services() {
    local -a services=()
    for service in "${!RULE_URLS[@]}"; do
        services+=("$service")
    done
    
    local -a selected_services=()
    
    while true; do
        show_service_menu
        echo -n "请输入选项 (多个选项用空格分隔): "
        read -r choices
        
        if [[ "$choices" =~ [Aa] ]]; then
            selected_services=("${services[@]}")
            log "已选择全部服务"
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
                    log "已添加: $service"
                fi
            fi
        done
    done
    
    printf '%s\n' "${selected_services[@]}"
}

# 生成 DNS hosts 配置
generate_dns_hosts() {
    local unlock_ip=$1
    shift
    local -a domain_suffixes=("$@")
    
    local hosts_json="{"
    local first=true
    
    for suffix in "${domain_suffixes[@]}"; do
        if [[ $first == true ]]; then
            first=false
        else
            hosts_json+=","
        fi
        
        # 添加主域名
        hosts_json+="\"$suffix\":\"$unlock_ip\""
        
        # 添加通配符域名
        hosts_json+=",\"*.$suffix\":\"$unlock_ip\""
    done
    
    hosts_json+="}"
    echo "$hosts_json"
}

# 生成 sing-box 配置
generate_singbox_config() {
    local unlock_ip=$1
    local connection_type=$2
    shift 2
    local -a selected_services=("$@")
    
    log "生成 sing-box 配置文件..."
    
    # 收集所有域名后缀
    local -a all_suffixes=()
    
    for service in "${selected_services[@]}"; do
        local json_file="$TEMP_DIR/${service// /_}.json"
        if [[ -f "$json_file" ]]; then
            while IFS= read -r suffix; do
                all_suffixes+=("$suffix")
            done < <(extract_domain_suffixes "$json_file")
        fi
    done
    
    # 去重
    local -a unique_suffixes=($(printf '%s\n' "${all_suffixes[@]}" | sort -u))
    
    log "共提取到 ${#unique_suffixes[@]} 个唯一域名"
    
    # 生成 DNS hosts 配置
    local hosts_config=$(generate_dns_hosts "$unlock_ip" "${unique_suffixes[@]}")
    
    # 生成域名后缀数组 (JSON 格式)
    local suffix_array="["
    local first=true
    for suffix in "${unique_suffixes[@]}"; do
        if [[ $first == true ]]; then
            first=false
        else
            suffix_array+=","
        fi
        suffix_array+="\"$suffix\""
    done
    suffix_array+="]"
    
    # 根据连接类型生成不同的 outbound 配置
    local outbound_config=""
    if [[ "$connection_type" == "direct" ]]; then
        outbound_config='"outbound": "direct"'
    else
        # 代理模式,需要用户提供代理配置
        outbound_config='"outbound": "proxy-out"'
    fi
    
    # 生成完整配置
    cat > "$OUTPUT_FILE" << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "hosts",
        "tag": "dns_unlock",
        "predefined": $hosts_config
      },
      {
        "type": "https",
        "tag": "dns_cloudflare",
        "server": "1.1.1.1",
        "server_port": 443
      },
      {
        "type": "https",
        "tag": "dns_google",
        "server": "8.8.8.8",
        "server_port": 443
      },
      {
        "type": "local",
        "tag": "dns_local"
      }
    ],
    "rules": [
      {
        "domain_suffix": $suffix_array,
        "server": "dns_unlock"
      }
    ],
    "final": "dns_cloudflare",
    "strategy": "prefer_ipv4",
    "independent_cache": true
  },
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "domain_suffix": $suffix_array,
        "action": "route-options",
        "override_address": "$unlock_ip"
      },
      {
        "domain_suffix": $suffix_array,
        "action": "route",
        $outbound_config
      }
    ],
    "auto_detect_interface": true,
    "final": "direct"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 7890
    }
  ],
  "outbounds": [
EOF

    # 添加 outbound 配置
    if [[ "$connection_type" == "direct" ]]; then
        cat >> "$OUTPUT_FILE" << 'EOF'
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
EOF
    else
        cat >> "$OUTPUT_FILE" << 'EOF'
    {
      "type": "shadowsocks",
      "tag": "proxy-out",
      "server": "YOUR_PROXY_SERVER",
      "server_port": 8388,
      "method": "aes-256-gcm",
      "password": "YOUR_PASSWORD"
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
EOF
    fi

    cat >> "$OUTPUT_FILE" << 'EOF'
  ]
}
EOF

    log "配置文件已生成: $OUTPUT_FILE"
}

# 主函数
main() {
    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║      sing-box DNS 解锁配置生成脚本                     ║
║                                                       ║
║  配合 SNI Proxy 使用,为被解锁机生成配置                ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # 创建临时目录
    mkdir -p "$TEMP_DIR"
    
    # 检查依赖
    if ! command -v jq &> /dev/null; then
        log_error "需要安装 jq: sudo apt install jq 或 sudo yum install jq"
        exit 1
    fi
    
    # 获取解锁机IP
    echo ""
    read -p "请输入解锁机的公网IP地址: " unlock_ip
    if [[ -z "$unlock_ip" ]]; then
        log_error "IP地址不能为空"
        exit 1
    fi
    
    # 选择连接类型
    echo ""
    echo "请选择连接方式:"
    echo "  [1] 直连 (被解锁机可以直接访问解锁机)"
    echo "  [2] 代理 (需要通过 SS/VMess 等代理访问解锁机)"
    echo ""
    read -p "请选择 (1/2): " conn_choice
    
    local connection_type="direct"
    if [[ "$conn_choice" == "2" ]]; then
        connection_type="proxy"
        log_warn "代理模式需要手动修改生成的配置文件中的代理服务器信息"
    fi
    
    # 选择服务
    local -a selected_services
    mapfile -t selected_services < <(select_services)
    
    # 下载规则
    echo ""
    log "开始下载规则文件..."
    for service in "${selected_services[@]}"; do
        download_rules "$service" "${RULE_URLS[$service]}" || true
    done
    
    # 生成配置
    echo ""
    generate_singbox_config "$unlock_ip" "$connection_type" "${selected_services[@]}"
    
    # 清理临时文件
    rm -rf "$TEMP_DIR"
    
    # 显示摘要
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  配置生成完成!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "配置文件: $OUTPUT_FILE"
    echo "解锁机IP: $unlock_ip"
    echo "连接方式: $connection_type"
    echo ""
    echo "已配置的服务:"
    for service in "${selected_services[@]}"; do
        echo "  ✓ $service"
    done
    echo ""
    
    if [[ "$connection_type" == "proxy" ]]; then
        echo -e "${YELLOW}重要提示:${NC}"
        echo "  请编辑 $OUTPUT_FILE,修改以下内容:"
        echo "  - YOUR_PROXY_SERVER: 代理服务器地址"
        echo "  - YOUR_PASSWORD: 代理密码"
        echo "  - 根据需要修改加密方法和端口"
        echo ""
    fi
    
    echo "使用方法:"
    echo "  1. 将配置文件复制到 sing-box 配置目录"
    echo "  2. 重启 sing-box: systemctl restart sing-box"
    echo "  3. 测试解锁效果"
    echo ""
}

# 运行主函数
main "$@"

