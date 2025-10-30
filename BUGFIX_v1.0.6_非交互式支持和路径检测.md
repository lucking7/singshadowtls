# Bug 修复报告: v1.0.6 - 非交互式支持和路径检测

## 修复日期
2024-01-XX

## 问题概述
根据测试结果,`install_sniproxy.sh` 脚本存在以下问题:
1. 无法在非交互式环境下运行(如 `curl | bash`)
2. Ubuntu 系统上 sniproxy 路径不正确导致服务启动失败
3. 缺少命令行参数支持,不便于自动化部署

## 修复的问题

### 问题 1: 非交互式环境运行失败

#### 问题描述
- **现象**: 通过 `curl | bash` 执行时报错 `/dev/tty: No such device or address`
- **影响**: 无法通过自动化脚本或 CI/CD 管道部署
- **根本原因**: 脚本多处使用 `< /dev/tty` 读取用户输入,在非交互式环境下不可用

#### 受影响的代码位置
- `check_network()`: 第 166 行
- `select_services()`: 第 389 行
- `configure_firewall()`: 第 606, 634, 642, 651, 667 行
- `main()`: 第 841 行

#### 修复方案
1. **添加环境检测函数**
   ```bash
   is_interactive() {
     [[ -t 0 ]] && [[ -z "$NON_INTERACTIVE" ]]
   }
   ```

2. **添加命令行参数支持**
   - `-h, --help`: 显示帮助信息
   - `-y, --yes`: 自动确认所有提示
   - `-n, --non-interactive`: 启用非交互式模式
   - `-a, --all-services`: 安装所有服务
   - `-s, --services SERVICES`: 指定服务列表

3. **添加环境变量支持**
   - `SNIPROXY_NON_INTERACTIVE=1`: 启用非交互式模式
   - `SNIPROXY_AUTO_CONFIRM=1`: 自动确认
   - `SNIPROXY_SERVICES="Netflix,Disney+"`: 预设服务

4. **修改交互式函数**
   - `select_services()`: 支持非交互式服务选择
   - `check_network()`: 非交互式模式下自动继续
   - `configure_firewall()`: 非交互式模式下跳过
   - `main()`: 非交互式模式下跳过确认

#### 使用示例
```bash
# 非交互式安装所有服务
sudo bash install_sniproxy.sh --yes --all-services

# 安装指定服务
sudo bash install_sniproxy.sh -y -s "Netflix,Disney+,OpenAI"

# 通过 curl 管道安装
curl -fsSL https://raw.githubusercontent.com/.../install_sniproxy.sh | \
  sudo SNIPROXY_SERVICES="Netflix,YouTube" bash -s -- --yes
```

### 问题 2: Ubuntu 系统 sniproxy 路径错误

#### 问题描述
- **现象**: systemd 服务启动失败,提示 `/usr/local/bin/sniproxy: No such file or directory`
- **影响**: Ubuntu/Debian 系统无法启动 sniproxy 服务
- **根本原因**: 
  - Ubuntu/Debian 通过 apt 安装的 sniproxy 在 `/usr/sbin/sniproxy`
  - CentOS/RHEL 源码编译的在 `/usr/local/bin/sniproxy`
  - 脚本硬编码为 `/usr/local/bin/sniproxy`

#### 受影响的代码位置
- `create_systemd_service()`: 第 263 行 (ExecStart 路径)
- `start_sniproxy()`: 第 690 行 (配置验证)
- `test_sniproxy()`: 第 755 行 (测试验证)

#### 修复方案
1. **添加路径检测函数**
   ```bash
   detect_sniproxy_path() {
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
       return 1
     fi
     
     SNIPROXY_BIN="$sniproxy_path"
     log_info "检测到 sniproxy 路径: $SNIPROXY_BIN"
   }
   ```

2. **动态生成 systemd 服务文件**
   ```bash
   ExecStart=${sniproxy_exec} -c /etc/sniproxy.conf
   ```

3. **所有调用使用检测到的路径**
   ```bash
   "$sniproxy_exec" -t -c "$SNIPROXY_CONF"
   ```

#### 检测优先级
1. `command -v sniproxy` (最可靠)
2. `/usr/sbin/sniproxy` (Ubuntu/Debian)
3. `/usr/local/bin/sniproxy` (CentOS/RHEL)

### 问题 3: 配置文件完整性验证

#### 验证结果
检查代码确认配置文件生成逻辑完整,包含所有必需的配置块:
- ✅ user 和 pidfile 配置
- ✅ error_log 配置
- ✅ resolver 配置
- ✅ listener 0.0.0.0:80 (HTTP)
- ✅ listener 0.0.0.0:443 (HTTPS)
- ✅ table 配置块

**结论**: 配置文件生成逻辑正确,无需修复。

### 问题 4: ERR trap 继承问题

#### 状态
已在 v1.0.5 中修复,本次更新保留修复:
```bash
# 保存当前的 ERR trap 并临时禁用它
local old_trap=$(trap -p ERR)
trap - ERR

# ... 处理服务 ...

# 恢复原来的 ERR trap
eval "$old_trap"
```

## 代码变更统计

### 新增功能
- 新增函数: `show_help()`, `parse_arguments()`, `is_interactive()`, `detect_sniproxy_path()`
- 新增全局变量: `SNIPROXY_BIN`, `NON_INTERACTIVE`, `AUTO_CONFIRM`, `SELECTED_SERVICES`, `ALL_SERVICES`
- 新增命令行参数: 5 个
- 新增环境变量: 3 个

### 修改的函数
- `select_services()`: 添加非交互式逻辑 (+40 行)
- `check_network()`: 添加非交互式跳过 (+6 行)
- `configure_firewall()`: 添加非交互式跳过 (+6 行)
- `create_systemd_service()`: 使用动态路径 (+3 行)
- `start_sniproxy()`: 使用动态路径 (+3 行)
- `test_sniproxy()`: 使用动态路径 (+3 行)
- `main()`: 添加参数解析和路径检测 (+10 行)

### 总计
- 新增代码: ~150 行
- 修改代码: ~70 行
- 删除代码: ~20 行
- 净增加: ~200 行

## 测试验证

### 静态测试
运行 `test_install_sniproxy.sh`:
```
✓ 帮助信息函数存在
✓ 参数解析函数存在
✓ 脚本语法正确
✓ 所有关键函数存在
✓ 环境变量支持完整
✓ 命令行参数支持完整
✓ 版本号已更新
✓ sniproxy 路径检测功能已实现
✓ 配置文件生成逻辑完整
✓ ERR trap 修复已应用
```

### 需要的动态测试(在 Linux 服务器上)

#### 测试场景 1: 交互式安装
```bash
sudo bash install_sniproxy.sh
# 预期: 正常显示菜单,可以选择服务
```

#### 测试场景 2: 非交互式安装所有服务
```bash
sudo bash install_sniproxy.sh -y -a
# 预期: 无需任何交互,自动安装所有服务
```

#### 测试场景 3: 非交互式安装指定服务
```bash
sudo bash install_sniproxy.sh -y -s "Netflix,Disney+"
# 预期: 只安装 Netflix 和 Disney+ 服务
```

#### 测试场景 4: 通过 curl 管道安装
```bash
curl -fsSL https://raw.githubusercontent.com/.../install_sniproxy.sh | \
  sudo SNIPROXY_SERVICES="Netflix" bash -s -- -y
# 预期: 成功安装,无需交互
```

#### 测试场景 5: Ubuntu 系统路径检测
```bash
# 在 Ubuntu 系统上
sudo bash install_sniproxy.sh -y -a
sudo systemctl status sniproxy
# 预期: 服务正常启动,使用 /usr/sbin/sniproxy
```

#### 测试场景 6: CentOS 系统路径检测
```bash
# 在 CentOS 系统上
sudo bash install_sniproxy.sh -y -a
sudo systemctl status sniproxy
# 预期: 服务正常启动,使用 /usr/local/bin/sniproxy
```

## 兼容性说明

### 向后兼容
- ✅ 完全兼容旧版本的交互式使用方式
- ✅ 配置文件格式完全兼容
- ✅ 不影响已安装的系统

### 系统要求
- Bash 4.0+ (支持关联数组)
- Ubuntu 18.04+ / Debian 9+ / CentOS 7+ / RHEL 7+ / Fedora 28+
- curl, jq, git (CentOS/RHEL)

### 已知限制
- macOS 默认 bash 3.2 不支持,需要安装 bash 4+
- 脚本仅在 Linux 服务器上运行

## 部署建议

### 升级步骤
1. 下载新版本脚本
2. 验证语法: `bash -n install_sniproxy.sh`
3. 在测试环境验证
4. 部署到生产环境

### 回滚方案
如果出现问题,可以使用 v1.0.5 版本:
```bash
curl -fsSL -o install_sniproxy.sh \
  https://raw.githubusercontent.com/lucking7/singshadowtls/v1.0.5/install_sniproxy.sh
```

## 相关文件
- `install_sniproxy.sh`: 主脚本
- `CHANGELOG_v1.0.6.md`: 详细更新日志
- `test_install_sniproxy.sh`: 测试脚本

## 维护者
- lucking7@github.com

## 参考链接
- GitHub 仓库: https://github.com/lucking7/singshadowtls
- 问题追踪: https://github.com/lucking7/singshadowtls/issues

