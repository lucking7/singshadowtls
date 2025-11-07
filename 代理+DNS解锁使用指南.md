# 代理 + DNS 解锁使用指南

## 功能说明

现在 sb.sh 脚本支持在同一台服务器上**同时运行代理服务（ShadowTLS/Shadowsocks）和 DNS 解锁功能**。

### 应用场景

```
┌─────────────────────────────────────────────────────────┐
│                   您的服务器                            │
│  ┌──────────────────┐    ┌─────────────────────────┐   │
│  │  代理服务        │    │  DNS 解锁服务           │   │
│  │  ShadowTLS/SS    │    │  本机 + 代理客户端      │   │
│  └──────────────────┘    └─────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
           ↑                           ↑
           │                           │
      代理连接                    DNS 查询
           │                           │
    ┌──────┴───────┐          ┌───────┴────────┐
    │  代理客户端  │          │  本机系统 DNS  │
    │  (手机/电脑) │          │   127.0.0.1:53 │
    └──────────────┘          └────────────────┘
```

### 核心优势

1. **代理客户端享受 DNS 解锁**
   - 通过代理连接的客户端自动享受 DNS 解锁服务
   - 无需客户端额外配置 DNS
   - 流媒体域名自动走解锁机 SmartDNS

2. **本机系统 DNS 解锁**
   - 服务器本机也可使用 DNS 解锁
   - 监听 127.0.0.1:53

3. **配置灵活**
   - 可以先安装代理，后添加 DNS 解锁
   - 可以选择覆盖或合并配置
   - 支持配置更新时保留现有设置

## 使用方法

### 场景 1：已有代理，添加 DNS 解锁（推荐）

这是最常见的场景，您已经在服务器上安装了代理服务，现在想添加 DNS 解锁功能。

#### 步骤 1：安装代理

```bash
sudo bash sb.sh
# 选择: 1) Install Sing-Box (Beta)
# 然后选择安装模式，例如:
# - Shadowsocks Only
# - ShadowTLS Separated
# - ShadowTLS Shared Port
# 等等...
```

✅ 代理安装完成，可以正常使用

#### 步骤 2：添加 DNS 解锁（合并模式）

```bash
sudo bash sb.sh
# 选择: 13) DNS 分流客户端 (被解锁机)
# 选择: 1) 部署 DNS 分流客户端
```

**重要：配置检测和选择**

脚本会自动检测到您已有代理配置，并显示：

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
检测到您已配置代理服务 (ShadowTLS/Shadowsocks)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

请选择操作模式:

  1) 代理 + DNS 解锁 (推荐)
     → 保留代理配置，添加 DNS 解锁功能
     → 代理客户端可享受 DNS 解锁服务
     → 本机系统也可使用 DNS 解锁

  2) 仅 DNS 解锁 (将清除代理配置)
     → 仅保留 DNS 解锁功能
     → 警告: 代理服务将停止工作

  0) 取消操作

请选择 [0-2]:
```

**选择 1** - 代理 + DNS 解锁（推荐）

#### 步骤 3：配置 DNS 解锁参数

按照提示输入：
- 解锁机 IP 地址
- 解锁机 SmartDNS 端口（默认 53）
- 流媒体服务选择（推荐选 0 全部）
- 公共 DNS 选择（推荐 Cloudflare）
- 是否启用广告拦截

#### 步骤 4：配置合并

脚本会自动执行以下步骤：

```
╔═══════════════════════════════════════════════════════╗
║  生成 sing-box 配置文件                              ║
╚═══════════════════════════════════════════════════════╝

[1/5] 备份现有配置...
✓ 已备份到: /etc/sing-box/config.json.bak.20250107_...
✓ 已提取代理配置到临时文件

[2/5] 生成 DNS 配置...
✓ DNS 配置生成完成

[3/5] 应用配置参数...
✓ 配置参数应用完成

[4/5] 合并代理配置...
✓ 代理配置合并完成
  → 保留了代理 inbounds 和 outbounds
  → 代理客户端可享受 DNS 解锁服务

[5/5] 验证配置文件...
✓ 配置文件验证通过
```

✅ **完成！** 现在您的服务器同时拥有代理和 DNS 解锁功能。

### 场景 2：一次性配置（先 DNS 后代理）

如果您想先配置 DNS 解锁，后配置代理：

#### 步骤 1：配置 DNS 解锁

```bash
sudo bash sb.sh
# 选择: 13) DNS 分流客户端 (被解锁机)
# 选择: 1) 部署 DNS 分流客户端
# 按提示配置参数
```

#### 步骤 2：安装代理

```bash
sudo bash sb.sh
# 选择: 1) Install Sing-Box (Beta)
# 选择安装模式
```

⚠️ **注意**: 安装代理会**覆盖** DNS 配置！

**解决方案**：重新执行步骤 1（添加 DNS 解锁），选择 "代理 + DNS 解锁" 模式。

### 场景 3：更新 DNS 配置（保留代理）

如果您想更新 DNS 解锁配置（如更换解锁机 IP），而保留代理配置：

```bash
sudo bash sb.sh
# 选择: 13) DNS 分流客户端 (被解锁机)
# 选择: 1) 部署 DNS 分流客户端
```

脚本会检测到您已有 "代理 + DNS" 配置，并自动进入合并模式，保留代理配置的同时更新 DNS 配置。

## 配置文件结构

合并后的配置文件包含：

```json
{
  "log": {...},

  "dns": {
    "servers": [
      {
        "tag": "unlock_dns",
        "address": "udp://解锁机IP:53"
      },
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query"
      }
    ],
    "rules": [
      {
        "rule_set": ["geosite-netflix", "geosite-disney", ...],
        "server": "unlock_dns"
      },
      {
        "server": "cloudflare"
      }
    ]
  },

  "inbounds": [
    {
      "type": "shadowtls",
      ...
    },
    {
      "type": "shadowsocks",
      ...
    }
  ],

  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],

  "route": {...},

  "services": [
    {
      "type": "resolved",
      "listen": "127.0.0.1",
      "listen_port": 53
    }
  ]
}
```

### DNS 工作原理

```
客户端通过代理连接
        ↓
  Sing-Box inbound
        ↓
    DNS 查询
        ↓
   DNS 分流规则
    ↙      ↘
流媒体域名   其他域名
    ↓         ↓
解锁机 DNS  Cloudflare
```

## 测试验证

### 测试 1：代理连接测试

在客户端配置代理并连接，测试代理是否正常工作。

### 测试 2：DNS 解锁测试

**在客户端**（通过代理连接后）：

```bash
# 测试流媒体域名是否走解锁 DNS
nslookup netflix.com

# 访问流媒体网站
# 如 Netflix, Disney+, ChatGPT 等
```

**在服务器本机**：

```bash
# 测试本机 DNS
nslookup netflix.com
```

### 测试 3：配置验证

```bash
# 查看配置文件
cat /etc/sing-box/config.json | jq

# 检查配置语法
sing-box check -c /etc/sing-box/config.json

# 查看服务状态
systemctl status sing-box

# 查看日志
journalctl -u sing-box -f
```

## 常见问题

### Q1: 代理和 DNS 解锁会互相影响吗？

**A**: 不会。它们是独立的功能：
- 代理服务通过 inbounds 提供
- DNS 服务通过顶层 DNS 配置提供
- 所有代理入站流量自动使用配置的 DNS

### Q2: 客户端需要单独配置 DNS 吗？

**A**: 不需要。通过代理连接的客户端自动使用服务器的 DNS 配置。

### Q3: 如果我只想要 DNS 解锁，不要代理怎么办？

**A**: 在配置时选择 "仅 DNS 解锁" 模式，会清除代理配置。

### Q4: 配置文件可以手动修改吗？

**A**: 可以，但建议：
1. 先备份: `cp /etc/sing-box/config.json /etc/sing-box/config.json.backup`
2. 修改后验证: `sing-box check -c /etc/sing-box/config.json`
3. 重启服务: `systemctl restart sing-box`

### Q5: 合并配置失败怎么办？

**A**: 脚本会自动恢复备份配置。如果需要手动恢复：

```bash
# 查看备份文件
ls -lh /etc/sing-box/*.bak*

# 恢复最新备份
cp /etc/sing-box/config.json.bak.XXXXXX /etc/sing-box/config.json

# 重启服务
systemctl restart sing-box
```

### Q6: 可以先安装代理，后面再考虑是否添加 DNS 吗？

**A**: 可以！先安装代理使用，随时可以通过选项 13 添加 DNS 解锁功能。

## 架构优势

### 1. 统一管理

```
单个 Sing-Box 进程
├── 代理服务（inbounds）
├── DNS 服务（dns + services）
└── 路由规则（route）
```

### 2. 资源高效

- 单个进程，资源占用低
- 共享配置和规则集
- 统一的日志和监控

### 3. 配置灵活

- 支持动态添加/删除功能
- 配置合并智能化
- 自动备份和恢复

## 技术细节

### 配置检测逻辑

```bash
detect_config_type()
├── none      - 无配置
├── proxy     - 仅代理
├── dns       - 仅 DNS
├── proxy_dns - 代理 + DNS
└── invalid   - 配置无效
```

### 配置合并流程

```
1. 检测现有配置类型
    ↓
2. 提取代理配置（inbounds, outbounds, route）
    ↓
3. 生成 DNS 配置
    ↓
4. 使用 jq 合并配置
    ↓
5. 验证合并后的配置
    ↓
6. 应用并重启服务
```

### jq 合并逻辑

```bash
jq --argjson inbounds "$inbounds" \
   --argjson outbounds "$outbounds" \
   --argjson route "$route" \
   '. + {
       inbounds: $inbounds,
       outbounds: ($outbounds + .outbounds | unique_by(.tag)),
       route: (合并 rule_set)
   }'
```

## 更新日志

### v3.4 (2025-01-07)

- ✅ 新增配置类型检测功能
- ✅ 新增配置智能合并功能
- ✅ 支持代理 + DNS 解锁共存
- ✅ 新增用户友好的配置选择界面
- ✅ 改进配置备份和恢复机制
- ✅ 优化步骤提示和进度显示

## 相关文档

- [主 README](README.md)
- [DNS 解锁教程](DNS解锁教程.md)
- [配置合并方案](config_merge_solution.md)
- [测试报告](测试报告.md)

## 支持和反馈

如遇到问题，请提供以下信息：

1. 配置类型（纯代理/纯 DNS/代理+DNS）
2. 操作步骤
3. 错误信息或日志
4. 配置文件备份

提交 Issue: https://github.com/lucking7/singshadowtls/issues
