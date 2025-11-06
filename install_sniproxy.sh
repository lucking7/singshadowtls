#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
# File: install_sniproxy.sh
# Description: SNI Proxy 自动化安装和配置脚本，支持流媒体解锁规则自动提取
# Maintainer: lucking7@github.com
# Version: 1.0.6
# Requires: Bash 4.0+, curl, jq, git (CentOS需要), autotools (CentOS需要)

set -Eeuo pipefail

# 版本与元信息
readonly SCRIPT_VERSION="1.0.6"
readonly MAINTAINER="lucking7@github.com"
readonly REQUIRES_BASH="4.0+"
readonly SCRIPT_BASENAME="$(basename "$0")"
readonly SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# 颜色定义（ANSI 转义码）
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'

# 兼容性：保留旧变量名
RED="$COLOR_RED"
GREEN="$COLOR_GREEN"
YELLOW="$COLOR_YELLOW"
BLUE="$COLOR_BLUE"
NC="$COLOR_RESET"

# 全局变量
TEMP_DIR="/tmp/sniproxy_install_$$"
BACKUP_DIR="/etc/sniproxy_backup_$(date +%Y%m%d_%H%M%S)"
readonly SNIPROXY_CONF="/etc/sniproxy.conf"
readonly LOG_FILE="/var/log/sniproxy_install.log"

# 运行时变量
SNIPROXY_BIN=""                                    # sniproxy 可执行文件路径
NON_INTERACTIVE="${SNIPROXY_NON_INTERACTIVE:-}"   # 非交互式模式
AUTO_CONFIRM="${SNIPROXY_AUTO_CONFIRM:-}"         # 自动确认
SELECTED_SERVICES="${SNIPROXY_SERVICES:-}"        # 预设服务列表
ALL_SERVICES=false                                 # 是否选择所有服务

# SmartDNS 相关变量
ENABLE_SMARTDNS="${SNIPROXY_ENABLE_SMARTDNS:-}"   # 是否启用 SmartDNS
SMARTDNS_MODE="${SNIPROXY_SMARTDNS_MODE:-}"       # SmartDNS 模式: server/local
ENABLE_AD_FILTER="${SNIPROXY_ENABLE_AD_FILTER:-}" # 是否启用广告过滤
DNS_CLIENT_IP="${SNIPROXY_DNS_CLIENT_IP:-}"       # DNS 客户端 IP（用于白名单）
readonly SMARTDNS_CONF="/etc/smartdns/smartdns.conf"
readonly SMARTDNS_DIR="/etc/smartdns"
SMARTDNS_VERSION=""                                # SmartDNS 版本号
SERVER_IP=""                                       # 本机 IP（解锁机 IP）

# 规则库 URL 映射
declare -A RULE_URLS
RULE_URLS["Netflix"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.json"
RULE_URLS["Disney+"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/disney.json"
RULE_URLS["OpenAI"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.json"
RULE_URLS["AI服务"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.json"
RULE_URLS["Amazon Prime"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/primevideo.json"
RULE_URLS["YouTube"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.json"
RULE_URLS["HBO"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/hbo.json"
RULE_URLS["Hulu"]="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/hulu.json"

# 清理函数（遵循 R4.6.2）
cleanup_temp_files() {
  if [[ -n "${TEMP_DIR:-}" ]] && [[ -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}

# 错误处理函数
on_error() {
  local exit_code=$1
  local line_number=$2
  log_error "脚本在第 $line_number 行发生错误，退出码: $exit_code"

  # 显示最后几行日志以帮助调试
  if [[ -f "$LOG_FILE" ]]; then
    echo "" >&2
    echo "=== 最后 10 行日志 ===" >&2
    tail -n 10 "$LOG_FILE" >&2
  fi

  cleanup_temp_files
}

# 设置 trap（遵循 R4.6.2）
trap cleanup_temp_files EXIT
trap 'on_error $? $LINENO' ERR

# 显示帮助信息
show_help() {
  cat << EOF
SNI Proxy 自动化安装和配置脚本 v${SCRIPT_VERSION}

用法: $SCRIPT_BASENAME [选项]

选项:
  -h, --help                    显示此帮助信息
  -y, --yes                     自动确认所有提示
  -n, --non-interactive         非交互式模式(需要指定服务)
  -a, --all-services            安装所有服务
  -s, --services SERVICES       指定要安装的服务(逗号分隔)
                                可用服务: Netflix, Disney+, OpenAI, AI服务,
                                         Amazon Prime, YouTube, HBO, Hulu

  SmartDNS 选项:
  --enable-smartdns             启用 SmartDNS 安装
  --smartdns-mode MODE          SmartDNS 模式: server(服务器模式) 或 local(本地模式)
  --enable-ad-filter            启用广告过滤功能
  --dns-client-ip IP            DNS 客户端 IP(用于防火墙白名单)

环境变量:
  SNIPROXY_NON_INTERACTIVE=1        启用非交互式模式
  SNIPROXY_AUTO_CONFIRM=1           自动确认所有提示
  SNIPROXY_SERVICES="..."           预设服务列表(逗号分隔)
  SNIPROXY_ENABLE_SMARTDNS=1        启用 SmartDNS
  SNIPROXY_SMARTDNS_MODE="server"   SmartDNS 模式
  SNIPROXY_ENABLE_AD_FILTER=1       启用广告过滤
  SNIPROXY_DNS_CLIENT_IP="IP"       DNS 客户端 IP

示例:
  # 交互式安装
  sudo $SCRIPT_BASENAME

  # 非交互式安装所有服务
  sudo $SCRIPT_BASENAME --yes --all-services

  # 安装指定服务
  sudo $SCRIPT_BASENAME -y -s "Netflix,Disney+,OpenAI"

  # 启用 SmartDNS (服务器模式)
  sudo $SCRIPT_BASENAME -y -a --enable-smartdns --smartdns-mode=server

  # 启用 SmartDNS (本地模式) + 广告过滤
  sudo $SCRIPT_BASENAME -y -a --enable-smartdns --smartdns-mode=local --enable-ad-filter

  # 使用环境变量
  SNIPROXY_SERVICES="Netflix,YouTube" SNIPROXY_ENABLE_SMARTDNS=1 sudo $SCRIPT_BASENAME -y

EOF
  exit 0
}

# 解析命令行参数
parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h|--help)
        show_help
        ;;
      -y|--yes)
        AUTO_CONFIRM=1
        shift
        ;;
      -n|--non-interactive)
        NON_INTERACTIVE=1
        shift
        ;;
      -a|--all-services)
        ALL_SERVICES=true
        shift
        ;;
      -s|--services)
        if [[ -n "${2:-}" ]]; then
          SELECTED_SERVICES="$2"
          shift 2
        else
          log_error "选项 $1 需要参数"
          exit 1
        fi
        ;;
      --enable-smartdns)
        ENABLE_SMARTDNS=1
        shift
        ;;
      --smartdns-mode)
        if [[ -n "${2:-}" ]]; then
          SMARTDNS_MODE="$2"
          shift 2
        else
          log_error "选项 $1 需要参数"
          exit 1
        fi
        ;;
      --smartdns-mode=*)
        SMARTDNS_MODE="${1#*=}"
        shift
        ;;
      --enable-ad-filter)
        ENABLE_AD_FILTER=1
        shift
        ;;
      --dns-client-ip)
        if [[ -n "${2:-}" ]]; then
          DNS_CLIENT_IP="$2"
          shift 2
        else
          log_error "选项 $1 需要参数"
          exit 1
        fi
        ;;
      --dns-client-ip=*)
        DNS_CLIENT_IP="${1#*=}"
        shift
        ;;
      *)
        log_error "未知选项: $1"
        echo "使用 --help 查看帮助信息"
        exit 1
        ;;
    esac
  done
}

# 检测是否为交互式环境
is_interactive() {
  # 检查是否显式设置为非交互式
  [[ -n "$NON_INTERACTIVE" ]] && return 1

  # 检查 stdin 是否是终端，或者 /dev/tty 是否可用
  # 这样即使通过 curl | bash 执行，只要终端可用就能交互
  [[ -t 0 ]] || [[ -c /dev/tty ]]
}

# 日志函数（遵循 R4.7.1）
log() {
  printf "${COLOR_GREEN}[%s]${COLOR_RESET} %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" | tee -a "$LOG_FILE"
}

log_error() {
  printf "${COLOR_RED}[ERROR][%s]${COLOR_RESET} %s\n" "$SCRIPT_BASENAME" "$1" >&2 | tee -a "$LOG_FILE"
}

log_warn() {
  printf "${COLOR_YELLOW}[WARN][%s]${COLOR_RESET} %s\n" "$SCRIPT_BASENAME" "$1" | tee -a "$LOG_FILE"
}

log_info() {
  printf "${COLOR_BLUE}[INFO][%s]${COLOR_RESET} %s\n" "$SCRIPT_BASENAME" "$1" | tee -a "$LOG_FILE"
}

# 依赖检查函数（遵循 R4.10.1）
ensure_command() {
  local cmd=$1
  local install_hint=${2:-"请参照 README 安装"}

  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "缺少依赖: $cmd。$install_hint"
    exit 69
  fi
}

# 检查所有必需依赖
check_dependencies() {
  log_info "检查必需依赖..."

  ensure_command "curl" "请安装: apt-get install curl 或 yum install curl"
  ensure_command "jq" "请安装: apt-get install jq 或 yum install jq"
  ensure_command "git" "请安装: apt-get install git 或 yum install git"
  ensure_command "make" "请安装: apt-get install build-essential 或 yum groupinstall 'Development Tools'"

  log_info "所有依赖检查通过"
}

# 检查是否为 root 用户
check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_error "此脚本必须以 root 权限运行"
    printf "%s\n" "请使用: sudo $0"
    exit 77
  fi
}

# 检测 sniproxy 可执行文件路径
detect_sniproxy_path() {
  log_info "检测 sniproxy 可执行文件路径..."

  local sniproxy_path=""

  # 优先使用 command -v 查找
  if command -v sniproxy >/dev/null 2>&1; then
    sniproxy_path=$(command -v sniproxy)
  elif [[ -x /usr/sbin/sniproxy ]]; then
    sniproxy_path="/usr/sbin/sniproxy"
  elif [[ -x /usr/local/bin/sniproxy ]]; then
    sniproxy_path="/usr/local/bin/sniproxy"
  else
    log_error "无法找到 sniproxy 可执行文件"
    log_error "请确保 sniproxy 已正确安装"
    return 1
  fi

  SNIPROXY_BIN="$sniproxy_path"
  log_info "检测到 sniproxy 路径: $SNIPROXY_BIN"
  return 0
}

# 检测操作系统
detect_os() {
  local os_id=""
  local os_version_id=""

  if [[ -f /etc/os-release ]]; then
    # 读取 /etc/os-release 到局部变量，避免污染全局变量
    # shellcheck source=/dev/null
    while IFS='=' read -r key value; do
      # 移除引号
      value="${value%\"}"
      value="${value#\"}"

      case "$key" in
        ID) os_id="$value" ;;
        VERSION_ID) os_version_id="$value" ;;
      esac
    done < /etc/os-release

    OS="${os_id:-unknown}"
    OS_VERSION="${os_version_id:-unknown}"
  elif [[ -f /etc/redhat-release ]]; then
    OS="centos"
    OS_VERSION="unknown"
  else
    log_error "无法检测操作系统类型"
    exit 71
  fi

  log_info "检测到操作系统: $OS $OS_VERSION"
}

# 检查网络连接
check_network() {
    log_info "检查网络连接..."

    if ! curl -s --connect-timeout 5 https://raw.githubusercontent.com > /dev/null 2>&1; then
        log_warn "无法连接到 GitHub,请检查网络连接"
        echo "提示: 如果在中国大陆,可能需要配置代理"

        if is_interactive && [[ -z "$AUTO_CONFIRM" ]]; then
            read -p "是否继续? (y/n): " continue_choice < /dev/tty
            if [[ ! $continue_choice =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            log_warn "非交互式模式,继续安装..."
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

# 安装 SNI Proxy
install_sniproxy() {
  log_info "开始安装 SNI Proxy..."

  case $OS in
    ubuntu|debian)
      # Ubuntu/Debian 使用官方包（更快更可靠）
      log_info "使用 apt 安装 sniproxy..."
      apt-get update -qq
      apt-get install -y sniproxy

      # 停止默认服务（我们会用自己的配置）
      systemctl stop sniproxy 2>/dev/null || true
      systemctl disable sniproxy 2>/dev/null || true
      ;;

    centos|rhel|fedora)
      # CentOS/RHEL/Fedora 需要源码编译
      log_info "从源码编译安装 sniproxy..."

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
      ;;

    *)
      log_error "不支持的操作系统: $OS"
      exit 71
      ;;
  esac

  log "SNI Proxy 安装完成"
}

# 创建 systemd 服务文件
create_systemd_service() {
    log_info "创建 systemd 服务文件..."

    # 使用检测到的 sniproxy 路径
    local sniproxy_exec="${SNIPROXY_BIN:-/usr/local/bin/sniproxy}"

    cat > /etc/systemd/system/sniproxy.service << EOF
[Unit]
Description=SNI Proxy
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sniproxy.pid
ExecStart=${sniproxy_exec} -c /etc/sniproxy.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "systemd 服务文件创建完成 (使用: $sniproxy_exec)"
}

# 从 JSON 提取域名
extract_domains_from_json() {
  local json_file=$1
  local domains=()

  # 验证文件存在且可读
  if [[ ! -f "$json_file" ]]; then
    log_error "extract_domains_from_json: 文件不存在: $json_file"
    return 1
  fi

  # 提取 domain 字段
  if jq -e '.rules[].domain[]' "$json_file" > /dev/null 2>&1; then
    while IFS= read -r domain; do
      if [[ -n "$domain" ]]; then
        domains+=("$domain")
      fi
    done < <(jq -r '.rules[].domain[]?' "$json_file" 2>/dev/null | grep -v "^null$" || true)
  fi

  # 提取 domain_suffix 字段
  if jq -e '.rules[].domain_suffix[]' "$json_file" > /dev/null 2>&1; then
    while IFS= read -r suffix; do
      if [[ -n "$suffix" ]]; then
        domains+=("$suffix")
      fi
    done < <(jq -r '.rules[].domain_suffix[]?' "$json_file" 2>/dev/null | grep -v "^null$" || true)
  fi

  # 输出去重后的域名（处理空数组情况）
  if [[ ${#domains[@]} -gt 0 ]]; then
    printf '%s\n' "${domains[@]}" | sort -u
  else
    # 数组为空时不输出任何内容（避免 set -u 错误）
    log_warn "extract_domains_from_json: 未从 $json_file 提取到任何域名"
    return 0
  fi
}

# 转换域名为 SNI Proxy 格式
convert_to_sniproxy_format() {
  local domain=$1

  # 验证域名不为空
  if [[ -z "$domain" ]]; then
    log_warn "convert_to_sniproxy_format: 域名为空，跳过"
    return 1
  fi

  # 移除前导点号
  domain="${domain#.}"

  # 转义点号（用于正则表达式）
  domain="${domain//./\\.}"

  # 添加通配符和结尾（使用 printf 避免转义问题）
  printf '    .*%s$ *\n' "$domain"
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

# 用户选择服务（支持交互式和非交互式模式）
select_services() {
  # 构建服务列表数组
  local -a services=()
  for service in "${!RULE_URLS[@]}"; do
    services+=("$service")
  done

  local -a selected_services=()

  # 非交互式模式处理
  if ! is_interactive; then
    log_info "非交互式模式,处理服务选择..." >&2

    # 优先级: --all-services > --services > 环境变量 SNIPROXY_SERVICES
    if [[ "$ALL_SERVICES" == true ]]; then
      selected_services=("${services[@]}")
      log_info "已选择全部服务 (--all-services)" >&2
    elif [[ -n "$SELECTED_SERVICES" ]]; then
      # 解析逗号分隔的服务列表
      IFS=',' read -ra service_list <<< "$SELECTED_SERVICES"
      for svc in "${service_list[@]}"; do
        # 去除前后空格
        svc=$(echo "$svc" | xargs)
        # 验证服务是否存在
        if [[ " ${services[@]} " =~ " ${svc} " ]]; then
          selected_services+=("$svc")
        else
          log_warn "未知服务: $svc (已忽略)" >&2
        fi
      done

      if [[ ${#selected_services[@]} -eq 0 ]]; then
        log_error "没有有效的服务被选择" >&2
        log_error "可用服务: ${services[*]}" >&2
        exit 1
      fi
    else
      # 非交互式模式下，如果没有指定服务，默认选择所有服务
      log_info "非交互式模式未指定服务,默认选择所有服务" >&2
      selected_services=("${services[@]}")
    fi
  else
    # 交互式模式
    # 显示菜单（直接输出到终端，不被捕获）
    echo "" >&2
    echo -e "${BLUE}========================================${NC}" >&2
    echo -e "${BLUE}  请选择需要解锁的服务 (可多选)${NC}" >&2
    echo -e "${BLUE}========================================${NC}" >&2
    echo "" >&2

    local i=1
    for service in "${services[@]}"; do
      echo "  [$i] $service" >&2
      ((i++))
    done

    echo "  [A] 全部选择" >&2
    echo "  [0] 完成选择" >&2
    echo "" >&2

    # 用户交互
    while true; do
      echo -n "请输入选项 (多个选项用空格分隔): " >&2
      read -r choices < /dev/tty

      if [[ "$choices" =~ [Aa] ]]; then
        selected_services=("${services[@]}")
        log_info "已选择全部服务" >&2
        break
      elif [[ "$choices" =~ 0 ]]; then
        if [[ ${#selected_services[@]} -eq 0 ]]; then
          log_warn "至少选择一个服务" >&2
          continue
        fi
        break
      fi

      for choice in $choices; do
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#services[@]} ]]; then
          local service="${services[$((choice-1))]}"
          if [[ ! " ${selected_services[@]} " =~ " ${service} " ]]; then
            selected_services+=("$service")
            log_info "已添加: $service" >&2
          fi
        else
          log_warn "无效选项: $choice" >&2
        fi
      done
    done
  fi

  echo "" >&2
  log "已选择 ${#selected_services[@]} 个服务:" >&2
  for service in "${selected_services[@]}"; do
    echo "  - $service" >&2
  done
  echo "" >&2

  # 只将选择的服务列表输出到 stdout（供 readarray 捕获）
  printf '%s\n' "${selected_services[@]}"
}

# 生成 SNI Proxy 配置文件
generate_sniproxy_config() {
  local -a selected_services=("$@")

  log_info "生成 SNI Proxy 配置文件..."

  # 验证参数
  if [[ ${#selected_services[@]} -eq 0 ]]; then
    log_error "generate_sniproxy_config: 没有选择任何服务"
    return 1
  fi

  # 备份原有配置
  if [[ -f "$SNIPROXY_CONF" ]]; then
    mkdir -p "$BACKUP_DIR" || {
      log_error "无法创建备份目录: $BACKUP_DIR"
      return 1
    }
    cp "$SNIPROXY_CONF" "$BACKUP_DIR/sniproxy.conf" || {
      log_error "无法备份配置文件"
      return 1
    }
    log_info "原配置已备份到: $BACKUP_DIR"
  fi

  # 创建配置文件头部
  log_info "写入配置文件头部..."
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

  # 检查写入是否成功
  if [[ ! -s "$SNIPROXY_CONF" ]]; then
    log_error "无法写入配置文件: $SNIPROXY_CONF"
    return 1
  fi

  # 处理每个选中的服务
  local total_domains=0
  local successful_services=0
  local failed_services=0

  # 保存当前的 ERR trap 并临时禁用它,避免单个服务失败触发 rollback
  local old_trap=$(trap -p ERR)
  trap - ERR

  for service in "${selected_services[@]}"; do
    local url="${RULE_URLS[$service]}"
    local json_file="$TEMP_DIR/${service// /_}.json"

    log_info "处理服务: $service"

    # 检查规则文件是否存在
    if [[ ! -f "$json_file" ]]; then
      log_warn "  ✗ 规则文件不存在: $json_file，跳过此服务"
      ((failed_services++))
      continue
    fi

    # 临时禁用严格错误处理，避免单个服务失败导致整个脚本退出
    set +e

    # 添加服务注释
    {
      echo ""
      echo "    # $service"
    } >> "$SNIPROXY_CONF"

    if [[ $? -ne 0 ]]; then
      log_error "  ✗ 无法写入服务注释: $service，跳过此服务"
      ((failed_services++))
      set -e
      continue
    fi

    local count=0
    local failed_count=0

    # 提取并转换域名
    while IFS= read -r domain; do
      if [[ -n "$domain" ]]; then
        if convert_to_sniproxy_format "$domain" >> "$SNIPROXY_CONF" 2>/dev/null; then
          ((count++))
          ((total_domains++))
        else
          ((failed_count++))
          log_warn "  ✗ 转换失败: $domain"
        fi
      fi
    done < <(extract_domains_from_json "$json_file" 2>/dev/null || true)

    # 恢复严格错误处理
    set -e

    # 统计结果
    if [[ $count -gt 0 ]]; then
      log_info "  ✓ $service: 添加了 $count 个域名规则"
      ((successful_services++))
      if [[ $failed_count -gt 0 ]]; then
        log_warn "  ⚠ $service: $failed_count 个域名转换失败"
      fi
    else
      log_warn "  ✗ $service: 没有提取到任何域名，跳过此服务"
      ((failed_services++))
    fi
  done

  # 恢复原来的 ERR trap
  eval "$old_trap"

  # 检查是否至少有一个服务成功
  if [[ $successful_services -eq 0 ]]; then
    log_error "所有服务处理失败，无法生成有效配置"
    return 1
  fi

  log_info "服务处理完成: 成功 $successful_services 个，失败 $failed_services 个"

  # 添加配置文件尾部
  log_info "写入配置文件尾部..."
  echo "}" >> "$SNIPROXY_CONF" || {
    log_error "无法写入配置文件尾部"
    return 1
  }

  # 验证配置文件
  if [[ ! -s "$SNIPROXY_CONF" ]]; then
    log_error "配置文件为空或不存在"
    return 1
  fi

  log "配置文件生成完成,共添加 $total_domains 个域名规则"
  log_info "配置文件路径: $SNIPROXY_CONF"

  # 显示配置文件统计
  local line_count=$(wc -l < "$SNIPROXY_CONF")
  log_info "配置文件总行数: $line_count"

  return 0
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

    # 非交互式模式跳过防火墙配置
    if ! is_interactive || [[ -n "$NON_INTERACTIVE" ]]; then
        log_warn "非交互式模式,跳过防火墙配置"
        log_warn "请手动配置防火墙规则,开放 80 和 443 端口"
        return
    fi

    if ! command -v ufw &> /dev/null; then
        log_warn "未检测到 UFW 防火墙"
        read -p "是否安装 UFW? (y/n): " install_ufw < /dev/tty
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

    read -p "是否配置防火墙规则? (y/n): " config_fw < /dev/tty

    if [[ $config_fw =~ ^[Yy]$ ]]; then
        echo ""
        echo "选择配置方式:"
        echo "  [1] 允许所有IP访问 (不推荐,有安全风险)"
        echo "  [2] 仅允许指定IP访问 (推荐)"
        echo ""
        read -p "请选择 (1/2): " fw_choice < /dev/tty

        case $fw_choice in
            1)
                ufw allow 80/tcp
                ufw allow 443/tcp
                log "已允许所有IP访问 80 和 443 端口"
                ;;
            2)
                read -p "请输入被解锁机的IP地址: " client_ip < /dev/tty
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
            read -p "UFW 未启用,是否启用? (y/n): " enable_ufw < /dev/tty
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

    # 使用检测到的 sniproxy 路径
    local sniproxy_exec="${SNIPROXY_BIN:-/usr/local/bin/sniproxy}"

    # 测试配置文件
    if "$sniproxy_exec" -t -c "$SNIPROXY_CONF"; then
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
    echo -e "${BLUE}SNI Proxy 配置摘要:${NC}"
    echo "  配置文件: $SNIPROXY_CONF"
    echo "  日志目录: /var/log/sniproxy/"
    echo "  备份目录: $BACKUP_DIR"
    echo ""
    echo -e "${BLUE}已启用的服务:${NC}"
    for service in "${selected_services[@]}"; do
        echo "  ✓ $service"
    done
    echo ""
    echo -e "${BLUE}SNI Proxy 服务状态:${NC}"
    systemctl status sniproxy --no-pager | head -n 10
    echo ""
    echo -e "${BLUE}SNI Proxy 监听端口:${NC}"
    ss -tlnp | grep sniproxy || netstat -tlnp | grep sniproxy
    echo ""

    # SmartDNS 摘要
    if [[ -n "$ENABLE_SMARTDNS" ]] && [[ "$ENABLE_SMARTDNS" == "1" ]]; then
        echo -e "${BLUE}SmartDNS 配置摘要:${NC}"
        echo "  配置文件: $SMARTDNS_CONF"
        echo "  部署模式: $SMARTDNS_MODE"
        echo "  解锁机IP: $SERVER_IP"
        if [[ -n "$ENABLE_AD_FILTER" ]] && [[ "$ENABLE_AD_FILTER" == "1" ]]; then
            echo "  广告过滤: 已启用"
        fi
        echo ""
        echo -e "${BLUE}SmartDNS 服务状态:${NC}"
        systemctl status smartdns --no-pager | head -n 10
        echo ""
        echo -e "${BLUE}SmartDNS 监听端口:${NC}"
        ss -ulnp | grep smartdns || netstat -ulnp | grep smartdns
        echo ""
    fi

    echo -e "${YELLOW}重要提示:${NC}"
    echo "  1. 请确保防火墙已正确配置"

    if [[ -n "$ENABLE_SMARTDNS" ]] && [[ "$ENABLE_SMARTDNS" == "1" ]]; then
        if [[ "$SMARTDNS_MODE" == "server" ]]; then
            echo "  2. 被解锁机需要修改 DNS 为: $SERVER_IP"
            echo "     编辑 /etc/resolv.conf，添加: nameserver $SERVER_IP"
        else
            echo "  2. 本地模式已启用，DNS 仅本机可用"
            echo "     本机 DNS 已自动配置为: 127.0.0.1"
        fi
        echo "  3. 查看 SNI Proxy 日志: journalctl -u sniproxy -f"
        echo "  4. 查看 SmartDNS 日志: journalctl -u smartdns -f"
        echo "  5. 重启 SNI Proxy: systemctl restart sniproxy"
        echo "  6. 重启 SmartDNS: systemctl restart smartdns"
    else
        echo "  2. 被解锁机需要配置 sing-box 指向本机IP"
        echo "  3. 查看日志: journalctl -u sniproxy -f"
        echo "  4. 重启服务: systemctl restart sniproxy"
        echo "  5. 查看配置: cat $SNIPROXY_CONF"
    fi
    echo ""

    # 获取本机IP
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "无法获取")
    fi
    echo -e "${GREEN}本机公网IP: $SERVER_IP${NC}"
    echo ""

    if [[ -n "$ENABLE_SMARTDNS" ]] && [[ "$ENABLE_SMARTDNS" == "1" ]]; then
        if [[ "$SMARTDNS_MODE" == "server" ]]; then
            echo "被解锁机配置步骤:"
            echo "  1. 修改 DNS: vim /etc/resolv.conf"
            echo "     添加: nameserver $SERVER_IP"
            echo "  2. 测试 DNS: nslookup netflix.com $SERVER_IP"
        else
            echo "本地模式配置完成，无需额外操作"
        fi
    else
        echo "在被解锁机的 sing-box 配置中,将域名解析到: $SERVER_IP"
    fi
    echo ""
}

# 测试功能
test_sniproxy() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  测试 SNI Proxy${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    # 使用检测到的 sniproxy 路径
    local sniproxy_exec="${SNIPROXY_BIN:-/usr/local/bin/sniproxy}"

    log_info "测试配置文件语法..."
    if "$sniproxy_exec" -t -c "$SNIPROXY_CONF"; then
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
        ss -tlnp | grep sniproxy || true
    fi

    echo ""
    log "测试完成"
}

# 检测 SmartDNS 架构
detect_smartdns_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      echo "x86_64-linux-all"
      ;;
    aarch64|arm64)
      echo "armv8-linux-all"
      ;;
    armv7l)
      echo "armv7-linux-all"
      ;;
    *)
      log_error "不支持的架构: $(uname -m)"
      return 1
      ;;
  esac
}

# 获取本机公网 IP
get_server_ip() {
  log_info "获取本机公网 IP..."

  # 尝试多个 IP 查询服务
  local ip=""
  ip=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null) || \
  ip=$(curl -s --connect-timeout 5 icanhazip.com 2>/dev/null) || \
  ip=$(curl -s --connect-timeout 5 api.ipify.org 2>/dev/null)

  if [[ -z "$ip" ]]; then
    log_error "无法获取本机公网 IP"
    return 1
  fi

  SERVER_IP="$ip"
  log_info "本机公网 IP: $SERVER_IP"
  return 0
}

# 安装 SmartDNS
install_smartdns() {
  log_info "开始安装 SmartDNS..."

  # 检测架构
  local arch
  arch=$(detect_smartdns_arch) || {
    log_error "无法检测系统架构"
    return 1
  }

  log_info "检测到架构: $arch"

  # 获取最新版本
  log_info "获取 SmartDNS 最新版本..."
  SMARTDNS_VERSION=$(curl -s https://api.github.com/repos/pymumu/smartdns/releases/latest | jq -r '.tag_name' | sed 's/Release//')

  if [[ -z "$SMARTDNS_VERSION" ]] || [[ "$SMARTDNS_VERSION" == "null" ]]; then
    log_error "无法获取 SmartDNS 版本信息"
    return 1
  fi

  log_info "最新版本: Release$SMARTDNS_VERSION"

  # 构建下载 URL
  local download_url="https://github.com/pymumu/smartdns/releases/download/Release${SMARTDNS_VERSION}/smartdns.${SMARTDNS_VERSION}.${arch}.tar.gz"
  local tar_file="$TEMP_DIR/smartdns.tar.gz"

  log_info "下载 SmartDNS..."
  if ! curl -fsSL "$download_url" -o "$tar_file"; then
    log_error "下载 SmartDNS 失败"
    log_error "URL: $download_url"
    return 1
  fi

  # 解压
  log_info "解压 SmartDNS..."
  cd "$TEMP_DIR"
  if ! tar -xzf "$tar_file"; then
    log_error "解压 SmartDNS 失败"
    return 1
  fi

  # 查找解压后的目录
  local smartdns_dir
  smartdns_dir=$(find "$TEMP_DIR" -maxdepth 1 -type d -name "smartdns*" | head -1)

  if [[ -z "$smartdns_dir" ]] || [[ ! -d "$smartdns_dir" ]]; then
    log_error "找不到 SmartDNS 解压目录"
    return 1
  fi

  cd "$smartdns_dir"

  # 执行安装脚本
  log_info "执行 SmartDNS 安装脚本..."
  if [[ -f "./install" ]]; then
    chmod +x ./install
    if ! ./install -i; then
      log_error "SmartDNS 安装脚本执行失败"
      return 1
    fi
  else
    log_error "找不到 SmartDNS 安装脚本"
    return 1
  fi

  log "SmartDNS 安装完成"
  return 0
}

# 从域名列表生成 SmartDNS address 规则
generate_smartdns_address_rules() {
  local json_file=$1
  local server_ip=$2

  # 提取域名并转换为 SmartDNS 格式
  while IFS= read -r domain; do
    if [[ -n "$domain" ]]; then
      # 移除前导点号
      domain="${domain#.}"
      # 输出 SmartDNS address 规则
      echo "address /${domain}/${server_ip}"
    fi
  done < <(extract_domains_from_json "$json_file" 2>/dev/null || true)
}

# 生成 SmartDNS 配置文件
generate_smartdns_config() {
  local -a selected_services=("$@")

  log_info "生成 SmartDNS 配置文件..."

  # 验证参数
  if [[ ${#selected_services[@]} -eq 0 ]]; then
    log_error "generate_smartdns_config: 没有选择任何服务"
    return 1
  fi

  # 确保有服务器 IP
  if [[ -z "$SERVER_IP" ]]; then
    get_server_ip || {
      log_error "无法获取服务器 IP，SmartDNS 配置生成失败"
      return 1
    }
  fi

  # 创建配置目录
  mkdir -p "$SMARTDNS_DIR" || {
    log_error "无法创建 SmartDNS 配置目录"
    return 1
  }

  # 备份原有配置
  if [[ -f "$SMARTDNS_CONF" ]]; then
    cp "$SMARTDNS_CONF" "$BACKUP_DIR/smartdns.conf" || {
      log_warn "无法备份 SmartDNS 配置文件"
    }
    log_info "原配置已备份到: $BACKUP_DIR/smartdns.conf"
  fi

  # 确定 bind 配置
  local bind_config
  if [[ "$SMARTDNS_MODE" == "local" ]]; then
    bind_config="bind :53@lo -no-dualstack-selection -no-speed-check"
    log_info "使用本地模式: 仅本地可访问"
  else
    bind_config="bind[::]:53@eth0 -no-dualstack-selection -no-speed-check"
    log_info "使用服务器模式: 允许外部访问"
  fi

  # 创建配置文件头部
  cat > "$SMARTDNS_CONF" << EOF
# SmartDNS 配置文件
# 自动生成于: $(date)
# 模式: $SMARTDNS_MODE

# 监听配置
$bind_config

# 性能优化
dualstack-ip-selection no
speed-check-mode none
serve-expired-prefetch-time 21600
prefetch-domain yes
cache-size 32768
cache-persist yes
cache-file /etc/smartdns/cache
serve-expired yes
serve-expired-ttl 259200
serve-expired-reply-ttl 3
cache-checkpoint-time 86400

# 上游 DNS 服务器
server 8.8.8.8
server 8.8.4.4
server 1.1.1.1

# 流媒体解锁规则
EOF

  # 处理每个选中的服务
  local total_rules=0
  local successful_services=0

  for service in "${selected_services[@]}"; do
    local json_file="$TEMP_DIR/${service// /_}.json"

    log_info "处理服务: $service"

    # 检查规则文件是否存在
    if [[ ! -f "$json_file" ]]; then
      log_warn "  ✗ 规则文件不存在: $json_file，跳过此服务"
      continue
    fi

    # 添加服务注释
    {
      echo ""
      echo "# $service"
    } >> "$SMARTDNS_CONF"

    # 生成并添加 address 规则
    local count=0
    while IFS= read -r rule; do
      if [[ -n "$rule" ]]; then
        echo "$rule" >> "$SMARTDNS_CONF"
        ((count++))
        ((total_rules++))
      fi
    done < <(generate_smartdns_address_rules "$json_file" "$SERVER_IP")

    if [[ $count -gt 0 ]]; then
      log_info "  ✓ $service: 添加了 $count 条解析规则"
      ((successful_services++))
    else
      log_warn "  ✗ $service: 没有提取到任何域名"
    fi
  done

  # 检查是否至少有一个服务成功
  if [[ $successful_services -eq 0 ]]; then
    log_error "所有服务处理失败，无法生成有效配置"
    return 1
  fi

  log "SmartDNS 配置文件生成完成，共添加 $total_rules 条解析规则"
  log_info "配置文件路径: $SMARTDNS_CONF"

  return 0
}

# 安装广告过滤规则
install_ad_filter() {
  log_info "安装广告过滤规则..."

  local ad_conf="$SMARTDNS_DIR/anti-ad-smartdns.conf"

  # 下载广告过滤规则
  if curl -fsSL "https://anti-ad.net/anti-ad-for-smartdns.conf" -o "$ad_conf"; then
    log "广告过滤规则下载成功"

    # 在主配置文件中添加引用
    if ! grep -q "anti-ad-smartdns.conf" "$SMARTDNS_CONF"; then
      echo "" >> "$SMARTDNS_CONF"
      echo "# 广告过滤" >> "$SMARTDNS_CONF"
      echo "conf-file $ad_conf" >> "$SMARTDNS_CONF"
      log "广告过滤规则已启用"
    fi

    return 0
  else
    log_warn "广告过滤规则下载失败"
    return 1
  fi
}

# 配置 DNS 端口防火墙
configure_dns_firewall() {
  log_info "配置 DNS 端口防火墙..."

  # 非交互式模式或本地模式跳过
  if ! is_interactive || [[ -n "$NON_INTERACTIVE" ]] || [[ "$SMARTDNS_MODE" == "local" ]]; then
    if [[ "$SMARTDNS_MODE" == "local" ]]; then
      log_info "本地模式无需配置 DNS 防火墙"
    else
      log_warn "非交互式模式，跳过 DNS 防火墙配置"
      log_warn "请手动配置防火墙规则，开放 53 端口"
    fi
    return 0
  fi

  # 检查 UFW
  if ! command -v ufw &> /dev/null; then
    log_warn "未检测到 UFW 防火墙，跳过 DNS 端口配置"
    return 0
  fi

  echo ""
  echo -e "${YELLOW}========================================${NC}"
  echo -e "${YELLOW}  DNS 端口防火墙配置${NC}"
  echo -e "${YELLOW}========================================${NC}"
  echo ""
  echo "SmartDNS 需要开放以下端口:"
  echo "  - 53/udp  (DNS)"
  echo ""
  echo "建议配置白名单，仅允许被解锁机访问"
  echo ""

  read -p "是否配置 DNS 防火墙规则? (y/n): " config_dns_fw < /dev/tty

  if [[ $config_dns_fw =~ ^[Yy]$ ]]; then
    echo ""
    echo "选择配置方式:"
    echo "  [1] 允许所有IP访问 (不推荐)"
    echo "  [2] 仅允许指定IP访问 (推荐)"
    echo ""
    read -p "请选择 (1/2): " dns_fw_choice < /dev/tty

    case $dns_fw_choice in
      1)
        ufw allow 53/udp
        log "已允许所有IP访问 53 端口"
        ;;
      2)
        # 如果有预设的 DNS 客户端 IP，使用它
        local client_ip="$DNS_CLIENT_IP"

        if [[ -z "$client_ip" ]]; then
          read -p "请输入被解锁机的IP地址: " client_ip < /dev/tty
        fi

        if [[ -n "$client_ip" ]]; then
          ufw allow from "$client_ip" to any port 53 proto udp
          log "已允许 $client_ip 访问 53 端口"
        else
          log_warn "未输入IP地址，跳过 DNS 防火墙配置"
        fi
        ;;
      *)
        log_warn "无效选择，跳过 DNS 防火墙配置"
        ;;
    esac
  fi
}

# 启动 SmartDNS
start_smartdns() {
  log_info "启动 SmartDNS..."

  # 检查配置文件
  if [[ ! -f "$SMARTDNS_CONF" ]]; then
    log_error "SmartDNS 配置文件不存在"
    return 1
  fi

  # 启动服务
  systemctl enable smartdns || {
    log_error "无法启用 SmartDNS 服务"
    return 1
  }

  systemctl restart smartdns || {
    log_error "SmartDNS 启动失败"
    systemctl status smartdns
    return 1
  }

  # 检查状态
  sleep 2
  if systemctl is-active --quiet smartdns; then
    log "SmartDNS 启动成功"
    return 0
  else
    log_error "SmartDNS 启动失败"
    systemctl status smartdns
    return 1
  fi
}

# 测试 SmartDNS
test_smartdns() {
  echo ""
  echo -e "${BLUE}========================================${NC}"
  echo -e "${BLUE}  测试 SmartDNS${NC}"
  echo -e "${BLUE}========================================${NC}"
  echo ""

  log_info "测试服务状态..."
  if systemctl is-active --quiet smartdns; then
    log "✓ 服务运行正常"
  else
    log_error "✗ 服务未运行"
    return 1
  fi

  log_info "测试端口监听..."
  if ss -ulnp | grep -q ":53 "; then
    log "✓ 端口 53 正在监听"
  else
    log_warn "✗ 端口监听异常"
    ss -ulnp | grep smartdns || true
  fi

  echo ""
  log "测试完成"
}

# 错误处理和回滚
rollback() {
  log_error "安装过程中出现错误,正在回滚..."

  # 恢复配置文件
  if [[ -d "$BACKUP_DIR" ]] && [[ -f "$BACKUP_DIR/sniproxy.conf" ]]; then
    cp "$BACKUP_DIR/sniproxy.conf" "$SNIPROXY_CONF"
    log_info "已恢复 SNI Proxy 配置文件"
  fi

  if [[ -d "$BACKUP_DIR" ]] && [[ -f "$BACKUP_DIR/smartdns.conf" ]]; then
    cp "$BACKUP_DIR/smartdns.conf" "$SMARTDNS_CONF"
    log_info "已恢复 SmartDNS 配置文件"
  fi

  # 停止服务
  systemctl stop sniproxy 2>/dev/null || true
  systemctl stop smartdns 2>/dev/null || true

  # 清理临时文件
  cleanup_temp_files

  log_error "安装失败,已回滚"
  exit 1
}

# 主函数
main() {
    # 解析命令行参数
    parse_arguments "$@"

    # 设置错误处理
    trap rollback ERR

    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║        SNI Proxy 自动化安装和配置脚本                  ║
║                                                       ║
║  功能: 自动安装 SNI Proxy 并配置流媒体解锁规则         ║
║  版本: 1.0.6                                          ║
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

    # 询问是否继续(非交互式模式跳过)
    if is_interactive && [[ -z "$AUTO_CONFIRM" ]]; then
        echo ""
        read -p "是否继续安装? (y/n): " continue_install < /dev/tty
        if [[ ! $continue_install =~ ^[Yy]$ ]]; then
            log_info "用户取消安装"
            exit 0
        fi
    else
        log_info "自动确认模式,继续安装..."
    fi

    # 安装依赖
    install_dependencies

    # 安装 SNI Proxy
    install_sniproxy

    # 检测 sniproxy 可执行文件路径
    detect_sniproxy_path

    # 创建 systemd 服务
    create_systemd_service

    # 创建日志目录
    create_log_directory

    # 用户选择服务
    local -a selected_services
    readarray -t selected_services < <(select_services)

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

    # SmartDNS 安装流程
    if is_interactive && [[ -z "$ENABLE_SMARTDNS" ]]; then
        echo ""
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}  SmartDNS 配置${NC}"
        echo -e "${BLUE}========================================${NC}"
        echo ""
        echo -e "${YELLOW}SmartDNS 是一个本地 DNS 服务器，可以实现:${NC}"
        echo "  - 自动将流媒体域名解析到解锁机 IP"
        echo "  - DNS 缓存加速"
        echo "  - 广告过滤（可选）"
        echo ""
        echo -e "${YELLOW}部署模式:${NC}"
        echo "  - 服务器模式: 为多台服务器提供 DNS 服务"
        echo "  - 本地模式: 仅为本机提供 DNS 服务"
        echo ""

        read -p "是否安装 SmartDNS? (y/n): " install_smartdns_choice < /dev/tty

        if [[ $install_smartdns_choice =~ ^[Yy]$ ]]; then
            ENABLE_SMARTDNS=1

            # 选择部署模式
            echo ""
            echo "选择 SmartDNS 部署模式:"
            echo "  [1] 服务器模式 (为多台服务器提供 DNS)"
            echo "  [2] 本地模式 (仅本机使用)"
            echo ""
            read -p "请选择 (1/2, 默认: 2): " smartdns_mode_choice < /dev/tty

            case "$smartdns_mode_choice" in
                1)
                    SMARTDNS_MODE="server"
                    ;;
                *)
                    SMARTDNS_MODE="local"
                    ;;
            esac

            # 询问是否启用广告过滤
            echo ""
            read -p "是否启用广告过滤? (y/n): " enable_ad_choice < /dev/tty
            if [[ $enable_ad_choice =~ ^[Yy]$ ]]; then
                ENABLE_AD_FILTER=1
            fi
        fi
    fi

    # 执行 SmartDNS 安装
    if [[ -n "$ENABLE_SMARTDNS" ]] && [[ "$ENABLE_SMARTDNS" == "1" ]]; then
        echo ""
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}  开始安装 SmartDNS${NC}"
        echo -e "${BLUE}========================================${NC}"
        echo ""

        # 验证模式
        if [[ -z "$SMARTDNS_MODE" ]]; then
            SMARTDNS_MODE="local"
            log_info "未指定模式，使用默认: local"
        fi

        if [[ "$SMARTDNS_MODE" != "server" ]] && [[ "$SMARTDNS_MODE" != "local" ]]; then
            log_error "无效的 SmartDNS 模式: $SMARTDNS_MODE (必须是 server 或 local)"
            exit 1
        fi

        # 获取服务器 IP
        get_server_ip || {
            log_error "无法获取服务器 IP，SmartDNS 安装失败"
            exit 1
        }

        # 安装 SmartDNS
        install_smartdns || {
            log_error "SmartDNS 安装失败"
            exit 1
        }

        # 生成配置文件
        echo ""
        generate_smartdns_config "${selected_services[@]}" || {
            log_error "SmartDNS 配置生成失败"
            exit 1
        }

        # 安装广告过滤
        if [[ -n "$ENABLE_AD_FILTER" ]] && [[ "$ENABLE_AD_FILTER" == "1" ]]; then
            echo ""
            install_ad_filter || log_warn "广告过滤安装失败，继续..."
        fi

        # 配置 DNS 防火墙
        if [[ "$SMARTDNS_MODE" == "server" ]]; then
            echo ""
            configure_dns_firewall
        fi

        # 启动 SmartDNS
        echo ""
        start_smartdns || {
            log_error "SmartDNS 启动失败"
            exit 1
        }

        # 测试 SmartDNS
        test_smartdns

        # 如果是本地模式，自动配置本机 DNS
        if [[ "$SMARTDNS_MODE" == "local" ]]; then
            echo ""
            log_info "配置本机 DNS..."

            # 备份 resolv.conf
            if [[ -f /etc/resolv.conf ]]; then
                cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf"
                log_info "已备份 /etc/resolv.conf"
            fi

            # 修改 DNS
            echo "nameserver 127.0.0.1" > /etc/resolv.conf
            log "本机 DNS 已配置为 127.0.0.1"
        fi
    fi

    # 显示摘要
    echo ""
    show_summary "${selected_services[@]}"

    # 清理临时文件（trap 会自动调用 cleanup_temp_files）
    log_info "清理临时文件..."
    cleanup_temp_files
    log "清理完成"

    log "安装完成!"
}

# 运行主函数
main "$@"

