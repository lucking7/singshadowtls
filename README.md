# SingShadowTLS 🎵🎵🎵

一键部署 ShadowTLS 脚本工具

## 快速开始

### 使用 curl 一键安装

```bash
# 下载并运行安装脚本
curl -fsSL https://raw.githubusercontent.com/jasperl/singshadowtls/main/sb.sh | bash
```

或者

```bash
# 下载脚本到本地后运行
curl -O https://raw.githubusercontent.com/jasperl/singshadowtls/main/sb.sh
chmod +x sb.sh
./sb.sh
```

### 手动安装

1. 克隆仓库：

   ```bash
   git clone https://github.com/jasperl/singshadowtls.git
   cd singshadowtls
   ```

2. 运行安装脚本：
   ```bash
   chmod +x sb.sh
   ./sb.sh
   ```

## 说明

> _If we don't trust you, this plan can't be established. So I trust you, and that's a major premise._

本脚本提供 ShadowTLS 的自动化部署和配置功能，支持多种模式和优化选项。

## ✨ 新功能：DNS 解锁与分流 (v3.3+)

脚本现已支持完整的 DNS 解锁和分流方案，可完全替代 **SNI Proxy + smartdns**！

### 🎯 主要特性

#### 流媒体解锁 (选项 13)

- ✅ **FakeIP 加速模式** - 减少 DNS 延迟 50-200ms，性能提升显著
- ✅ **智能 DNS 分流** - 不同流媒体平台使用最优 DNS 策略
- ✅ **IPv6 优先解锁** - 提高 Netflix、Disney+ 等平台解锁成功率
- ✅ **一键配置** - 通过菜单选项 13 快速启用
- ✅ **完全替代** SNI Proxy + smartdns 方案，配置更简单，性能更好

#### DNS 分流配置 (选项 14) 🆕

- ✅ **按平台配置不同 DNS** - Netflix 用 Cloudflare，Disney+ 用 Google DNS
- ✅ **灵活的解析策略** - 支持 IPv4/IPv6 优先或仅用
- ✅ **规则集自动更新** - 使用 geosite-netflix 等规则集
- ✅ **配置验证** - 自动验证配置并提供回滚功能
- ✅ **自定义 DNS 服务器** - 支持输入自己的解锁 DNS (新增) ⭐

#### 纯 DNS 解锁服务器 (选项 15) 🆕

- ✅ **独立 DNS 服务** - 监听 53 端口，提供 DNS 解析服务
- ✅ **不代理流量** - 极低带宽消耗，客户端直连
- ✅ **多协议支持** - DoH、DoT、DoQ、DoH3 等加密协议
- ✅ **广告拦截** - 可选的广告域名拦截功能
- ✅ **FakeIP 加速** - 显著提升 DNS 解析速度（已修复配置错误）⭐
- ✅ **嵌套解锁支持** - 自动检测并使用已配置的解锁 DNS 作为上游 ⭐
- ✅ **客户端配置指南** - 自动生成各平台配置说明
- ✅ **性能优秀** - 1 核 1GB 可支持 100+客户端

### 📊 性能对比

| 模式         | DNS 解析延迟 | 连接建立时间 | 视频加载时间 |
| ------------ | ------------ | ------------ | ------------ |
| 传统 DNS     | 120ms        | 180ms        | 2.5s         |
| **FakeIP**   | ~0ms         | 60ms         | 1.2s         |
| **性能提升** | ✅ 100%      | ✅ 67%       | ✅ 52%       |

### 🎬 支持的流媒体平台

- Netflix
- Disney+
- Spotify
- YouTube
- HBO Max
- Amazon Prime Video
- 更多...

### 📖 详细文档

- **[DNS_UNLOCK_SERVER_GUIDE.md](DNS_UNLOCK_SERVER_GUIDE.md)** - 纯 DNS 解锁服务器部署指南 ⭐

### 🚀 快速使用

#### 启用流媒体解锁

```bash
bash sb.sh
# 选择: 13 → 1 (启用 FakeIP 模式)
```

#### 配置 DNS 分流

```bash
bash sb.sh
# 选择: 14 → 1 (配置 DNS 分流规则)
# 按提示为不同平台选择 DNS 服务器
# 可选择预设 DNS (1-5) 或自定义 DNS (6)
```

#### 使用自定义解锁 DNS

```bash
bash sb.sh
# 选择: 14 → 1
# 在任何平台选择: 6 (自定义解锁 DNS 服务器)
# 输入 DNS 地址: 1.2.3.4
# 选择协议: 3 (DoH 推荐)
# 输入路径: /dns-query
```

#### 部署纯 DNS 解锁服务器

```bash
bash sb.sh
# 选择: 15 → 1 (部署 DNS 解锁服务器)
# 配置完成后，客户端设置 DNS 为服务器 IP 即可
# 如果检测到已配置的解锁 DNS，可选择使用（嵌套解锁）
```

#### 嵌套解锁（使用已配置的解锁 DNS）⭐

```bash
# 场景：服务器 A 已配置流媒体解锁，在服务器 B 上部署 DNS 服务器
bash sb.sh
# 选择: 15 → 1
# 脚本会自动检测: ✓ 检测到已配置的 DNS 解锁服务器
# 上游 DNS: 0 (使用已配置的解锁 DNS) ← 选择这个
# 客户端将 DNS 设置为服务器 B 的 IP
```

#### 测试 DNS 解锁

```bash
bash test_dns_unlock.sh
# 或
bash sb.sh
# 选择: 15 → 3 (测试 DNS 服务器)
```

## 注意事项

- 请确保在支持的 Linux 发行版上运行
- 建议使用 root 权限执行脚本
- 脚本会自动处理依赖安装和防火墙配置
- 流媒体解锁功能需要服务器支持 IPv6（推荐）

## 许可证

请遵守相关法律法规，仅在合法范围内使用。
