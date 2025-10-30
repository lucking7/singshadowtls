#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# 测试 install_sniproxy.sh 的非交互式功能

set -e

echo "========================================="
echo "测试 install_sniproxy.sh 非交互式功能"
echo "========================================="
echo ""

# 测试 1: 帮助信息内容检查
echo "测试 1: 检查帮助信息内容"
echo ""
if grep -q "show_help()" install_sniproxy.sh && \
   grep -q "SNI Proxy 自动化安装和配置脚本" install_sniproxy.sh; then
    echo "✓ 帮助信息函数存在"
else
    echo "✗ 帮助信息函数不存在"
    exit 1
fi
echo ""

# 测试 2: 参数解析函数检查
echo "测试 2: 检查参数解析函数"
echo ""
if grep -q "parse_arguments()" install_sniproxy.sh && \
   grep -q "未知选项" install_sniproxy.sh; then
    echo "✓ 参数解析函数存在"
else
    echo "✗ 参数解析函数不存在"
    exit 1
fi
echo ""

# 测试 3: 语法检查
echo "测试 3: 脚本语法检查"
echo "命令: bash -n install_sniproxy.sh"
echo ""
if bash -n install_sniproxy.sh; then
    echo "✓ 脚本语法正确"
else
    echo "✗ 脚本语法错误"
    exit 1
fi
echo ""

# 测试 4: 检查关键函数
echo "测试 4: 检查关键函数是否存在"
echo ""
functions=(
    "show_help"
    "parse_arguments"
    "is_interactive"
    "detect_sniproxy_path"
    "select_services"
)

for func in "${functions[@]}"; do
    if grep -q "^${func}()" install_sniproxy.sh; then
        echo "✓ 函数 $func 存在"
    else
        echo "✗ 函数 $func 不存在"
        exit 1
    fi
done
echo ""

# 测试 5: 检查环境变量支持
echo "测试 5: 检查环境变量支持"
echo ""
env_vars=(
    "SNIPROXY_NON_INTERACTIVE"
    "SNIPROXY_AUTO_CONFIRM"
    "SNIPROXY_SERVICES"
)

for var in "${env_vars[@]}"; do
    if grep -q "$var" install_sniproxy.sh; then
        echo "✓ 环境变量 $var 已支持"
    else
        echo "✗ 环境变量 $var 未支持"
        exit 1
    fi
done
echo ""

# 测试 6: 检查命令行参数支持
echo "测试 6: 检查命令行参数支持"
echo ""
params=(
    "help"
    "yes"
    "non-interactive"
    "all-services"
    "services"
)

for param in "${params[@]}"; do
    if grep -q -- "--${param}" install_sniproxy.sh; then
        echo "✓ 参数 --${param} 已支持"
    else
        echo "✗ 参数 --${param} 未支持"
        exit 1
    fi
done
echo ""

# 测试 7: 检查版本号
echo "测试 7: 检查版本号"
echo ""
if grep -q 'SCRIPT_VERSION="1.0.6"' install_sniproxy.sh; then
    echo "✓ 版本号已更新为 1.0.6"
else
    echo "✗ 版本号未更新"
    exit 1
fi
echo ""

# 测试 8: 检查 sniproxy 路径检测
echo "测试 8: 检查 sniproxy 路径检测功能"
echo ""
if grep -q "detect_sniproxy_path()" install_sniproxy.sh && \
   grep -q "SNIPROXY_BIN=" install_sniproxy.sh; then
    echo "✓ sniproxy 路径检测功能已实现"
else
    echo "✗ sniproxy 路径检测功能未实现"
    exit 1
fi
echo ""

# 测试 9: 检查配置文件完整性
echo "测试 9: 检查配置文件生成逻辑"
echo ""
config_sections=(
    "listener 0.0.0.0:80"
    "listener 0.0.0.0:443"
    "resolver"
    "table"
)

for section in "${config_sections[@]}"; do
    if grep -q "$section" install_sniproxy.sh; then
        echo "✓ 配置段 '$section' 存在"
    else
        echo "✗ 配置段 '$section' 不存在"
        exit 1
    fi
done
echo ""

# 测试 10: 检查 ERR trap 修复
echo "测试 10: 检查 ERR trap 修复"
echo ""
if grep -q "local old_trap=\$(trap -p ERR)" install_sniproxy.sh && \
   grep -q 'eval "$old_trap"' install_sniproxy.sh; then
    echo "✓ ERR trap 修复已应用"
else
    echo "✗ ERR trap 修复未应用"
    exit 1
fi
echo ""

echo "========================================="
echo "所有测试通过! ✓"
echo "========================================="
echo ""
echo "注意事项:"
echo "1. 这些测试只验证脚本的静态特性"
echo "2. 完整功能测试需要在 Linux 服务器上运行"
echo "3. 需要 root 权限和网络连接"
echo ""

