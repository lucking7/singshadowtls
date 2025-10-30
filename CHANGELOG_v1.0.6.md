# SNI Proxy 安装脚本 v1.0.6 更新日志

## 发布日期
2024-01-XX

## 主要更新

### 1. 非交互式模式支持 🎯
解决了脚本在 `curl | bash` 等非交互式环境下无法运行的问题。

#### 新增命令行参数
- `-h, --help`: 显示帮助信息
- `-y, --yes`: 自动确认所有提示
- `-n, --non-interactive`: 启用非交互式模式
- `-a, --all-services`: 安装所有服务
- `-s, --services SERVICES`: 指定要安装的服务(逗号分隔)

#### 新增环境变量支持
- `SNIPROXY_NON_INTERACTIVE=1`: 启用非交互式模式
- `SNIPROXY_AUTO_CONFIRM=1`: 自动确认所有提示
- `SNIPROXY_SERVICES="Netflix,Disney+,..."`: 预设服务列表

#### 使用示例

**交互式安装(默认)**
```bash
sudo bash install_sniproxy.sh
```

**非交互式安装所有服务**
```bash
sudo bash install_sniproxy.sh --yes --all-services
```

**安装指定服务**
```bash
sudo bash install_sniproxy.sh -y -s "Netflix,Disney+,OpenAI"
```

**通过 curl 管道安装**
```bash
curl -fsSL https://raw.githubusercontent.com/lucking7/singshadowtls/main/install_sniproxy.sh | \
  sudo SNIPROXY_SERVICES="Netflix,YouTube" bash -s -- --yes
```

**使用环境变量**
```bash
SNIPROXY_SERVICES="Netflix,YouTube" sudo bash install_sniproxy.sh -y
```

### 2. 自动检测 sniproxy 可执行文件路径 🔍
修复了不同系统上 sniproxy 路径不一致的问题。

#### 问题背景
- Ubuntu/Debian 通过 apt 安装: `/usr/sbin/sniproxy`
- CentOS/RHEL 源码编译: `/usr/local/bin/sniproxy`
- 之前硬编码为 `/usr/local/bin/sniproxy` 导致 Ubuntu 系统启动失败

#### 解决方案
- 新增 `detect_sniproxy_path()` 函数
- 按优先级自动检测:
  1. `command -v sniproxy`
  2. `/usr/sbin/sniproxy`
  3. `/usr/local/bin/sniproxy`
- 动态生成 systemd 服务文件
- 配置验证和测试使用检测到的路径

### 3. 改进错误处理 ✅
- 非交互式模式下自动跳过防火墙配置(避免安全风险)
- 网络检查失败时在非交互式模式下自动继续
- 改进端口监听测试的错误处理

### 4. 代码优化
- 添加 `is_interactive()` 函数检测运行环境
- 添加 `parse_arguments()` 函数处理命令行参数
- 添加 `show_help()` 函数显示详细帮助信息
- 改进 `select_services()` 函数支持多种服务选择方式

## 修复的问题

### 问题 1: 非交互式环境运行失败
**现象**: 通过 `curl | bash` 执行时报错 `/dev/tty: No such device or address`

**原因**: 脚本多处使用 `< /dev/tty` 读取用户输入,在非交互式环境下不可用

**修复**: 
- 添加环境检测
- 支持命令行参数和环境变量
- 非交互式模式下跳过所有交互式提示

### 问题 2: Ubuntu 系统 sniproxy 启动失败
**现象**: systemd 服务启动失败,提示找不到 `/usr/local/bin/sniproxy`

**原因**: Ubuntu 通过 apt 安装的 sniproxy 在 `/usr/sbin/sniproxy`

**修复**: 
- 自动检测 sniproxy 路径
- 动态生成 systemd 服务文件
- 所有 sniproxy 调用使用检测到的路径

### 问题 3: 配置文件生成不完整
**现象**: 之前版本可能缺少 listener 配置块

**验证**: 检查代码确认配置文件生成逻辑完整,包含:
- user 和 pidfile 配置
- error_log 配置
- resolver 配置
- listener 0.0.0.0:80 (HTTP)
- listener 0.0.0.0:443 (HTTPS)
- table 配置块

## 兼容性

### 支持的系统
- Ubuntu 18.04+
- Debian 9+
- CentOS 7+
- RHEL 7+
- Fedora 28+

### 依赖要求
- Bash 4.0+ (支持关联数组)
- curl
- jq
- git (CentOS/RHEL 需要)
- autotools (CentOS/RHEL 需要)

## 升级指南

### 从 v1.0.5 升级
直接下载新版本脚本即可,无需卸载旧版本:

```bash
# 下载新版本
curl -fsSL -o install_sniproxy.sh \
  https://raw.githubusercontent.com/lucking7/singshadowtls/main/install_sniproxy.sh

# 添加执行权限
chmod +x install_sniproxy.sh

# 运行安装
sudo ./install_sniproxy.sh --help
```

### 配置文件兼容性
- 配置文件格式完全兼容
- 如果已有配置文件,脚本会自动备份
- 备份位置: `/etc/sniproxy_backup_YYYYMMDD_HHMMSS/`

## 测试建议

### 测试场景 1: 交互式安装
```bash
sudo bash install_sniproxy.sh
# 按提示选择服务
```

### 测试场景 2: 非交互式安装
```bash
sudo bash install_sniproxy.sh -y -a
# 应该自动安装所有服务,无需任何交互
```

### 测试场景 3: 指定服务安装
```bash
sudo bash install_sniproxy.sh -y -s "Netflix,Disney+"
# 应该只安装 Netflix 和 Disney+ 服务
```

### 测试场景 4: 通过 curl 管道安装
```bash
curl -fsSL https://raw.githubusercontent.com/lucking7/singshadowtls/main/install_sniproxy.sh | \
  sudo SNIPROXY_SERVICES="Netflix" bash -s -- -y
# 应该能够成功安装,无需交互
```

### 验证安装
```bash
# 检查服务状态
sudo systemctl status sniproxy

# 检查端口监听
sudo ss -tlnp | grep sniproxy

# 检查配置文件
sudo cat /etc/sniproxy.conf

# 查看日志
sudo journalctl -u sniproxy -f
```

## 已知问题

### macOS 开发环境
- macOS 默认 bash 版本为 3.2,不支持关联数组
- 脚本仅在 Linux 服务器上运行,macOS 仅用于开发
- 如需在 macOS 测试,请安装 bash 4+: `brew install bash`

## 贡献者
- lucking7@github.com

## 相关链接
- GitHub 仓库: https://github.com/lucking7/singshadowtls
- 问题反馈: https://github.com/lucking7/singshadowtls/issues

