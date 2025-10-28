# 纯 DNS 解锁服务器部署指南

## 📋 功能说明

纯 DNS 解锁服务器只提供 DNS 解析服务，不代理流量。客户端只需将 DNS 设置为服务器 IP 即可实现流媒体解锁。

### 🆕 v3.5 新增功能

1. **修复 FakeIP 配置错误**

   - ✅ FakeIP 服务器不再作为第一个 DNS 服务器
   - ✅ 真实 DNS 服务器优先，FakeIP 服务器在后
   - ✅ 符合 sing-box 配置要求

2. **嵌套解锁支持（增强版）** ⭐
   - ✅ 自动检测本机已配置的 DNS 解锁服务器
   - ✅ 用户确认是否使用检测到的解锁 DNS
   - ✅ 支持手动输入其他服务器的解锁 DNS
   - ✅ 支持 6 种 DNS 协议（UDP、TCP、DoH、DoT、DoQ、DoH3）
   - ✅ 灵活配置端口和路径
   - ⚠️ 注意：此行为可能违反某些服务商的 TOS

---

## 🚀 使用方法

### 方案一：使用公共 DNS 作为上游

**适用场景：** 在支持流媒体解锁的服务器上部署

```bash
bash sb.sh
# 选择: 15 (纯 DNS 解锁服务器配置)
# 选择: 1 (部署纯 DNS 解锁服务器)

# 配置选项
监听地址: 0.0.0.0 (默认)
监听端口: 53 (默认)
上游 DNS: 5 (全部公共 DNS) 或 1 (Cloudflare)
广告拦截: Y (推荐)
FakeIP: Y (推荐，提升性能)
```

**生成的配置：**

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns_cloudflare",
        "type": "https",
        "server": "1.1.1.1"
      },
      {
        "tag": "dns_fakeip",
        "type": "fakeip",
        "inet4_range": "198.18.0.0/15"
      }
    ]
  }
}
```

### 方案二：嵌套解锁 - 使用本机已配置的解锁 DNS ⭐

**适用场景：** 服务器已配置流媒体解锁，现在部署 DNS 服务器

**步骤：**

```bash
bash sb.sh
# 选择: 15 (纯 DNS 解锁服务器配置)
# 选择: 1 (部署纯 DNS 解锁服务器)

# 脚本自动检测
✓ 检测到本机已配置的 DNS 解锁服务器: dns_cf
  类型: https
  服务器: 1.1.1.1

# 用户确认
是否使用此解锁 DNS 作为上游（嵌套解锁）? [Y/n]: Y

# 配置选项
监听地址: 0.0.0.0
监听端口: 53
公共 DNS: 0 (不使用公共 DNS，仅使用嵌套解锁)
FakeIP: Y
广告拦截: Y
```

**工作原理：**

```
客户端 → 本机 DNS 服务器 → 本机解锁 DNS → 流媒体网站
```

---

### 方案三：嵌套解锁 - 使用其他服务器的解锁 DNS ⭐⭐

**适用场景：** 服务器 A (1.2.3.4) 已配置解锁，在服务器 B 上部署 DNS 服务器

**步骤：**

```bash
bash sb.sh
# 选择: 15 (纯 DNS 解锁服务器配置)
# 选择: 1 (部署纯 DNS 解锁服务器)

# 不使用本机解锁 DNS（如果有检测到）
是否使用此解锁 DNS 作为上游（嵌套解锁）? [Y/n]: n

# 手动配置其他服务器的解锁 DNS
是否使用其他服务器的解锁 DNS 作为上游（嵌套解锁）? [y/N]: y

# 配置上游解锁 DNS 服务器
请输入解锁 DNS 服务器地址: 1.2.3.4

选择 DNS 协议类型:
  1) UDP (传统 DNS, 端口 53)
  2) TCP (传统 DNS over TCP, 端口 53)
  3) DoH (DNS-over-HTTPS, 端口 443) 推荐
  4) DoT (DNS-over-TLS, 端口 853)
  5) DoQ (DNS-over-QUIC, 端口 853)
  6) DoH3 (DNS-over-HTTP/3, 端口 443)
请选择 [1-6, 默认: 3]: 3

请输入 DoH 路径 [默认: /dns-query]: /dns-query
DNS 端口 [默认: 443]: 443

# 配置摘要
上游解锁 DNS 配置摘要:
  服务器: 1.2.3.4
  类型: https
  端口: 443
  路径: /dns-query
确认配置? [Y/n]: Y

# 其他配置
监听地址: 0.0.0.0
监听端口: 53
公共 DNS: 1 (Cloudflare，作为备用)
FakeIP: Y
广告拦截: Y
```

**工作原理：**

```
客户端 → 服务器 B (DNS 服务器) → 服务器 A (解锁 DNS) → 流媒体网站
```

---

## 📊 配置对比

### FakeIP 配置修复前后对比

**❌ 修复前（错误配置）：**

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns_fakeip", // ❌ FakeIP 作为第一个
        "type": "fakeip"
      },
      {
        "tag": "dns_cloudflare",
        "type": "https",
        "server": "1.1.1.1"
      }
    ]
  }
}
```

**错误信息：**

```
FATAL[0000] initialize DNS server[0]: default server cannot be fakeip
```

**✅ 修复后（正确配置）：**

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns_cloudflare", // ✅ 真实 DNS 作为第一个
        "type": "https",
        "server": "1.1.1.1"
      },
      {
        "tag": "dns_fakeip", // ✅ FakeIP 在后面
        "type": "fakeip"
      }
    ]
  }
}
```

---

## 🔧 嵌套解锁配置示例

### 示例 1: 服务器 A 已配置 Cloudflare DNS 解锁

**服务器 A 配置：**

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns_cf",
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443,
        "path": "/dns-query"
      }
    ],
    "rules": [
      {
        "rule_set": ["geosite-netflix"],
        "server": "dns_cf",
        "strategy": "ipv6_only"
      }
    ]
  }
}
```

**服务器 B 自动生成的配置：**

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns_unlock_upstream", // 自动从服务器 A 复制
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443,
        "path": "/dns-query"
      },
      {
        "tag": "dns_fakeip",
        "type": "fakeip"
      }
    ],
    "rules": [
      {
        "rule_set": ["geosite-netflix"],
        "server": "dns_unlock_upstream", // 使用上游解锁 DNS
        "strategy": "ipv6_only"
      }
    ]
  }
}
```

### 示例 2: 服务器 A 使用自定义 DoH DNS

**服务器 A 配置：**

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns_custom_unlock",
        "type": "https",
        "server": "192.168.1.100",
        "server_port": 443,
        "path": "/dns-query"
      }
    ]
  }
}
```

**服务器 B 自动生成的配置：**

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns_unlock_upstream",
        "type": "https",
        "server": "192.168.1.100", // 自动复制自定义 DNS
        "server_port": 443,
        "path": "/dns-query"
      }
    ]
  }
}
```

---

## ✅ 部署后验证

### 1. 检查配置文件

```bash
# 查看 DNS 服务器配置
jq '.dns.servers' /etc/sing-box/config.json

# 查看 DNS 规则
jq '.dns.rules' /etc/sing-box/config.json

# 验证配置
sing-box check -c /etc/sing-box/config.json
```

### 2. 检查服务状态

```bash
# 查看服务状态
systemctl status sing-box

# 查看日志
journalctl -u sing-box -f

# 查看 DNS 日志
tail -f /var/log/sing-box/dns-unlock.log
```

### 3. 测试 DNS 解析

```bash
# 从客户端测试
nslookup netflix.com <服务器IP>
dig @<服务器IP> netflix.com

# 从服务器本地测试
nslookup netflix.com 127.0.0.1
```

---

## 🎯 使用场景

### 场景 1: 单服务器解锁

```
客户端 → DNS 服务器 (Cloudflare DNS) → Netflix
```

**配置：**

- 上游 DNS: Cloudflare (选项 1)
- FakeIP: 启用
- 广告拦截: 启用

### 场景 2: 嵌套解锁

```
客户端 → 服务器 B (DNS 服务器) → 服务器 A (解锁 DNS) → Netflix
```

**配置：**

- 服务器 A: 配置流媒体 DNS 解锁
- 服务器 B: 使用服务器 A 的解锁 DNS (选项 0)
- FakeIP: 启用

### 场景 3: 多服务器共享解锁

```
客户端 1 ┐
客户端 2 ├→ DNS 服务器 (嵌套解锁) → 解锁服务器 → Netflix
客户端 3 ┘
```

**优势：**

- 只需一台解锁服务器
- 其他服务器通过 DNS 共享解锁能力
- 降低成本

---

## ⚠️ 注意事项

### 1. FakeIP 使用

- ✅ **推荐启用** - 显著提升 DNS 解析速度
- ✅ **自动配置** - 脚本已修复配置顺序问题
- ⚠️ **兼容性** - 某些应用可能不兼容 FakeIP

### 2. 嵌套解锁

- ⚠️ **TOS 风险** - 可能违反服务商的服务条款
- ⚠️ **性能影响** - 增加一层 DNS 查询延迟
- ✅ **成本优势** - 可以共享解锁能力

### 3. 防火墙配置

```bash
# UFW
ufw allow 53/udp comment "DNS"
ufw allow 53/tcp comment "DNS"

# iptables
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
```

---

## 🐛 故障排除

### 问题 1: 配置验证失败 - "default server cannot be fakeip"

**原因：** FakeIP 服务器作为第一个 DNS 服务器

**解决：**

- ✅ 已在 v3.5 中修复
- 真实 DNS 服务器现在优先于 FakeIP

### 问题 2: 未检测到已配置的解锁 DNS

**检查：**

```bash
# 查看当前配置
jq '.dns.rules[] | select(.rule_set and (.rule_set | contains(["geosite-netflix"])))' /etc/sing-box/config.json
```

**解决：**

- 确保已配置流媒体 DNS 规则
- 重新运行部署脚本

### 问题 3: DNS 解析失败

**检查：**

```bash
# 查看日志
journalctl -u sing-box -n 50

# 测试上游 DNS
dig @1.1.1.1 netflix.com
```

---

## 📚 相关文档

- [README.md](README.md) - 项目说明
- [DNS_ROUTING_GUIDE.md](DNS_ROUTING_GUIDE.md) - DNS 分流配置指南（已删除）
- [DNS_UNLOCK_ADVANCED_GUIDE.md](DNS_UNLOCK_ADVANCED_GUIDE.md) - DNS 解锁高级指南（已删除）

---

**版本：** v3.5  
**更新时间：** 2024-01-XX  
**适用版本：** sing-box 1.12.0+
