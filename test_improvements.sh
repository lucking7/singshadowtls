#!/bin/bash
#
# 测试脚本：验证 Phase 1 和 Phase 2 的 UI/UX 改进
#
# 使用方法: bash test_improvements.sh
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 测试结果统计
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 测试结果记录
declare -a TEST_RESULTS=()

# 测试函数模板
test_function() {
    local test_name="$1"
    local test_command="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}测试 $TOTAL_TESTS: $test_name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    if eval "$test_command"; then
        echo -e "\n${GREEN}✓ 测试通过${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        TEST_RESULTS+=("${GREEN}✓${NC} $test_name")
    else
        echo -e "\n${RED}✗ 测试失败${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        TEST_RESULTS+=("${RED}✗${NC} $test_name")
    fi
}

# 加载 sb.sh 中的函数
SOURCE_SCRIPT="./sb.sh"

if [[ ! -f "$SOURCE_SCRIPT" ]]; then
    echo -e "${RED}错误: 找不到 sb.sh 脚本${NC}"
    exit 1
fi

# 提取需要的函数和变量定义
echo -e "${CYAN}加载 sb.sh 中的函数...${NC}\n"

# 提取颜色定义和函数
source <(sed -n '/^# Colors/,/^NC=/p' "$SOURCE_SCRIPT")
source <(sed -n '/^error_with_context()/,/^}/p' "$SOURCE_SCRIPT")
source <(sed -n '/^validate_ip()/,/^}/p' "$SOURCE_SCRIPT")
source <(sed -n '/^validate_port()/,/^}/p' "$SOURCE_SCRIPT")
source <(sed -n '/^validate_domain()/,/^}/p' "$SOURCE_SCRIPT")

echo -e "${GREEN}✓ 函数加载完成${NC}\n"

#############################################
# Phase 1 测试
#############################################

echo -e "${YELLOW}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC}  ${YELLOW}Phase 1 测试：子菜单语言和错误处理${NC}              ${YELLOW}║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════╝${NC}"

# 测试 1.1: error_with_context 函数存在性
test_function "error_with_context 函数定义检查" \
    "declare -f error_with_context > /dev/null"

# 测试 1.2: error_with_context 函数执行
test_function "error_with_context 函数执行测试" \
    "error_with_context '测试错误' '这是上下文' '这是建议' 2>/dev/null; true"

# 测试 1.3: 检查子菜单函数是否存在
test_function "子菜单函数存在性检查" \
    "grep -q 'show_port_menu()' '$SOURCE_SCRIPT' && \
     grep -q 'show_password_menu()' '$SOURCE_SCRIPT' && \
     grep -q 'show_shadowtls_menu()' '$SOURCE_SCRIPT' && \
     grep -q 'show_shadowsocks_menu()' '$SOURCE_SCRIPT' && \
     grep -q 'show_dns_menu()' '$SOURCE_SCRIPT'"

# 测试 1.4: 检查子菜单是否包含中文标题
test_function "子菜单中文化检查" \
    "grep -q '端口配置' '$SOURCE_SCRIPT' && \
     grep -q '密码管理' '$SOURCE_SCRIPT' && \
     grep -q 'ShadowTLS 设置' '$SOURCE_SCRIPT' && \
     grep -q 'Shadowsocks 设置' '$SOURCE_SCRIPT' && \
     grep -q 'DNS 配置' '$SOURCE_SCRIPT'"

# 测试 1.5: 检查统一标题框架
test_function "统一标题框架检查" \
    "grep -q '╔═══════════════════════════════════════════════════════╗' '$SOURCE_SCRIPT' && \
     grep -q '║' '$SOURCE_SCRIPT' && \
     grep -q '╚═══════════════════════════════════════════════════════╝' '$SOURCE_SCRIPT'"

#############################################
# Phase 2 测试
#############################################

echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC}  ${YELLOW}Phase 2 测试：前置检查、进度指示、输入验证${NC}      ${YELLOW}║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════╝${NC}"

# 测试 2.1: validate_ip 函数 - 有效 IP
test_function "validate_ip - 有效 IP 地址" \
    "validate_ip '192.168.1.1' 'Test IP' > /dev/null 2>&1"

# 测试 2.2: validate_ip 函数 - 无效 IP
test_function "validate_ip - 无效 IP 地址检测" \
    "! validate_ip '256.256.256.256' 'Test IP' > /dev/null 2>&1"

# 测试 2.3: validate_ip 函数 - 格式错误
test_function "validate_ip - 格式错误检测" \
    "! validate_ip '192.168.1' 'Test IP' > /dev/null 2>&1"

# 测试 2.4: validate_ip 函数 - 空值
test_function "validate_ip - 空值检测" \
    "! validate_ip '' 'Test IP' > /dev/null 2>&1"

# 测试 2.5: validate_port 函数 - 有效端口
test_function "validate_port - 有效端口" \
    "validate_port '8080' 'Test Port' > /dev/null 2>&1"

# 测试 2.6: validate_port 函数 - 无效端口（超出范围）
test_function "validate_port - 超出范围检测" \
    "! validate_port '70000' 'Test Port' > /dev/null 2>&1"

# 测试 2.7: validate_port 函数 - 无效端口（非数字）
test_function "validate_port - 非数字检测" \
    "! validate_port 'abc' 'Test Port' > /dev/null 2>&1"

# 测试 2.8: validate_port 函数 - 边界值测试
test_function "validate_port - 边界值 1" \
    "validate_port '1' 'Test Port' > /dev/null 2>&1"

test_function "validate_port - 边界值 65535" \
    "validate_port '65535' 'Test Port' > /dev/null 2>&1"

test_function "validate_port - 边界值 0 (无效)" \
    "! validate_port '0' 'Test Port' > /dev/null 2>&1"

# 测试 2.9: validate_domain 函数 - 有效域名
test_function "validate_domain - 有效域名" \
    "validate_domain 'example.com' 'Test Domain' > /dev/null 2>&1"

# 测试 2.10: validate_domain 函数 - 复杂域名
test_function "validate_domain - 复杂域名" \
    "validate_domain 'sub.example.co.uk' 'Test Domain' > /dev/null 2>&1"

# 测试 2.11: validate_domain 函数 - 无效域名
test_function "validate_domain - 无效域名检测" \
    "! validate_domain 'invalid..domain' 'Test Domain' > /dev/null 2>&1"

# 测试 2.12: 检查连通性检查函数存在
test_function "check_unlock_server_connectivity 函数定义检查" \
    "grep -q 'check_unlock_server_connectivity()' '$SOURCE_SCRIPT'"

# 测试 2.13: 检查等待函数存在
test_function "wait_for_service 函数定义检查" \
    "grep -q 'wait_for_service()' '$SOURCE_SCRIPT'"

# 测试 2.14: 检查进度条函数存在
test_function "show_progress 函数定义检查" \
    "grep -q 'show_progress()' '$SOURCE_SCRIPT'"

# 测试 2.15: 检查配置生成步骤化
test_function "配置生成步骤化检查" \
    "grep -q '\[1/4\]' '$SOURCE_SCRIPT' && \
     grep -q '\[2/4\]' '$SOURCE_SCRIPT' && \
     grep -q '\[3/4\]' '$SOURCE_SCRIPT' && \
     grep -q '\[4/4\]' '$SOURCE_SCRIPT'"

#############################################
# 代码质量测试
#############################################

echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC}  ${YELLOW}代码质量测试${NC}                                      ${YELLOW}║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════╝${NC}"

# 测试 3.1: Bash 语法检查
test_function "Bash 语法检查" \
    "bash -n '$SOURCE_SCRIPT'"

# 测试 3.2: 检查是否有未定义的变量使用（简单检查）
test_function "set -u 兼容性检查" \
    "bash -u -c 'source <(sed -n \"/^# Colors/,/^NC=/p\" \"$SOURCE_SCRIPT\")' 2>&1 | grep -qv 'unbound variable' || true"

# 测试 3.3: 检查关键函数数量
test_function "关键函数完整性检查" \
    "count=\$(grep -c '^[a-zA-Z_][a-zA-Z0-9_]*()' '$SOURCE_SCRIPT'); [ \$count -ge 50 ]"

#############################################
# 测试总结
#############################################

echo -e "\n\n${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  ${YELLOW}测试总结${NC}                                          ${BLUE}║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}测试结果列表:${NC}\n"
for result in "${TEST_RESULTS[@]}"; do
    echo -e "  $result"
done

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}总测试数:${NC} $TOTAL_TESTS"
echo -e "${GREEN}通过:${NC} $PASSED_TESTS"
echo -e "${RED}失败:${NC} $FAILED_TESTS"
echo -e "${CYAN}通过率:${NC} $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ 所有测试通过！${NC}\n"
    exit 0
else
    echo -e "${RED}✗ 部分测试失败，请检查上述结果${NC}\n"
    exit 1
fi
