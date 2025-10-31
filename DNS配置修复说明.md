# sing-box DNS 配置修复说明

## 问题描述

### 错误信息
```
FATAL[0000] initialize DNS server[0]: default server cannot be fakeip
```

### 根本原因

根据 sing-box 官方文档 (`docs/configuration/dns/index.zh.md`)：

> **final**
> 
> 默认 DNS 服务器的标签。
> 
> **默认使用第一个服务器。**

**问题：** FakeIP 类型的 DNS 服务器被放在了 `dns.servers` 数组的第一位，导致 sing-box 将其作为默认 DNS 服务器，但 FakeIP 不能作为默认服务器。

---

## 修复方案

### 核心原则

1. **DNS 服务器数组的第一个元素**是默认 DNS 服务器（如果没有指定 `dns.final`）
2. **FakeIP 不能作为默认服务器**，必须放在数组后面
3. **通过 `dns.final` 明确指定**默认服务器（推荐）
4. **通过 DNS 规则引用** FakeIP 服务器

---

## 修复内容

### 1. 初始配置生成 (第 1233-1267 行)

**修复前（错误）：**
```json
"dns": {
  "servers": [
    {
      "tag": "dns_fakeip",      // ❌ FakeIP 在第一位
      "type": "fakeip",
      ...
    },
    {
      "tag": "dns_cf",
      "type": "https",
      ...
    },
    ...
  ]
}
```

**修复后（正确）：**
```json
"dns": {
  "servers": [
    {
      "tag": "dns_cf",          // ✅ 常规 DNS 在第一位
      "type": "https",
      "server": "1.1.1.1"
    },
    {
      "tag": "dns_google",
      "type": "https",
      "server": "8.8.8.8"
    },
    {
      "tag": "dns_resolver",
      "type": "local"
    },
    {
      "tag": "dns_fakeip",      // ✅ FakeIP 在后面
      "type": "fakeip",
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    },
    {
      "tag": "dns_block",
      "type": "hosts",
      "predefined": {}
    }
  ],
  "final": "dns_cf",            // ✅ 明确指定默认 DNS
  "strategy": "prefer_ipv4",
  "independent_cache": true,
  ...
}
```

---

### 2. DNS 分流配置更新 (第 2631-2668, 2681-2717, 2727-2757 行)

**修复内容：**
- 在所有 jq 命令中添加 `| .dns.final = "dns_cloudflare"`
- 确保 FakeIP 和 block 服务器通过 `+ (.dns.servers | map(select(.tag == "dns_fakeip" or .tag == "dns_block")))` 追加到数组末尾

**示例：**
```bash
jq '.dns.servers = [
    {
        "tag": "dns_cloudflare",
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443
    },
    ...
] + (.dns.servers | map(select(.tag == "dns_fakeip" or .tag == "dns_block"))) |
.dns.final = "dns_cloudflare"' \
/etc/sing-box/config.json > /tmp/config_temp.json
```

---

### 3. 恢复默认 DNS 配置 (第 2876-2894 行)

**修复内容：**
- 添加 `| .dns.final = "dns_cf"`

**修复后：**
```bash
jq '.dns.servers = [
    {
        "tag": "dns_cf",
        "type": "https",
        "server": "1.1.1.1"
    },
    {
        "tag": "dns_google",
        "type": "https",
        "server": "8.8.8.8"
    },
    {
        "tag": "dns_local",
        "type": "local"
    }
] + (.dns.servers | map(select(.tag == "dns_fakeip" or .tag == "dns_block"))) |
.dns.final = "dns_cf"' \
/etc/sing-box/config.json > /tmp/config_temp.json
```

---

### 4. DNS 解锁服务器配置 (第 3262-3425 行)

**已有正确逻辑：**
- 第 3262 行注释："首先添加真实的上游 DNS 服务器（FakeIP 不能作为第一个）"
- 第 3397 行注释："现在添加 FakeIP 服务器（在真实 DNS 之后）"

**新增修复：**
- 在第 3421 行添加 `"final": "dns_cloudflare"`

---

## 推荐的 DNS 服务器顺序

```
1. 常规 DNS 服务器 (https/udp/tcp/tls/quic)
   ├── Cloudflare (1.1.1.1)
   ├── Google (8.8.8.8)
   ├── AdGuard (94.140.14.14)
   └── Quad9 (9.9.9.9)

2. 本地 DNS (local)

3. FakeIP 服务器 (fakeip)  ← 必须在后面

4. 拦截 DNS (hosts)
```

---

## 配置验证

### 验证步骤

```bash
# 1. 检查配置文件语法
sing-box check -c /etc/sing-box/config.json

# 2. 查看 DNS 服务器顺序
jq '.dns.servers[] | {tag, type}' /etc/sing-box/config.json

# 3. 查看默认 DNS 服务器
jq '.dns.final' /etc/sing-box/config.json

# 4. 重启服务
systemctl restart sing-box

# 5. 查看服务状态
systemctl status sing-box

# 6. 查看日志
journalctl -u sing-box -f
```

---

### 正确的输出示例

**DNS 服务器顺序：**
```json
{
  "tag": "dns_cf",
  "type": "https"
}
{
  "tag": "dns_google",
  "type": "https"
}
{
  "tag": "dns_resolver",
  "type": "local"
}
{
  "tag": "dns_fakeip",
  "type": "fakeip"
}
{
  "tag": "dns_block",
  "type": "hosts"
}
```

**默认 DNS 服务器：**
```json
"dns_cf"
```

---

## 技术细节

### FakeIP 的工作原理

1. **FakeIP 返回假 IP** (198.18.0.0/15 范围)
2. **sing-box 拦截假 IP 的流量**
3. **根据域名规则路由**到真实目标
4. **不能处理常规 DNS 查询**

### 为什么 FakeIP 不能作为默认服务器？

- FakeIP 只返回假 IP，不能解析真实 IP 地址
- 如果作为默认服务器，所有 DNS 查询都会返回假 IP
- 会导致不匹配规则的域名无法正常解析

### 正确的使用方式

```json
{
  "dns": {
    "servers": [
      {
        "type": "https",        // ✅ 默认服务器
        "server": "1.1.1.1"
      },
      {
        "type": "fakeip",       // ✅ 通过规则引用
        "tag": "fakeip"
      }
    ],
    "rules": [
      {
        "rule_set": ["geosite-netflix"],
        "server": "fakeip",     // ✅ 只对特定域名使用 FakeIP
        "query_type": ["A", "AAAA"]
      }
    ],
    "final": "dns_cloudflare"   // ✅ 明确指定默认服务器
  }
}
```

---

## 参考文档

- [sing-box DNS 配置](docs/configuration/dns/index.zh.md)
- [sing-box DNS 服务器](docs/configuration/dns/server/index.zh.md)
- [sing-box FakeIP 服务器](docs/configuration/dns/server/fakeip.zh.md)
- [sing-box 迁移指南](docs/migration.zh.md)

---

## 总结

### 修复要点

1. ✅ **初始配置生成**：FakeIP 移到数组后面，添加 `"final": "dns_cf"`
2. ✅ **DNS 分流配置**：所有 jq 命令添加 `| .dns.final = "dns_cloudflare"`
3. ✅ **恢复默认配置**：添加 `| .dns.final = "dns_cf"`
4. ✅ **DNS 解锁服务器**：添加 `"final": "dns_cloudflare"`

### 影响范围

- ✅ 所有新生成的配置都符合 sing-box 规范
- ✅ 现有配置更新时会自动修复顺序
- ✅ 不会影响已有的正确配置

### 兼容性

- ✅ 向后兼容：旧配置仍然有效
- ✅ 向前兼容：符合 sing-box 1.12.0+ 规范
- ✅ 不影响功能：FakeIP 功能正常工作

---

**修复完成！** 🎉

