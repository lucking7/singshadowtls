# sb.sh v3.3 - DNS 配置合规性修复报告

## 修复日期
2025-10-30

## 修复版本
v3.2 → v3.3

---

## 📋 修复概述

根据 sing-box 官方文档 (`docs/configuration/dns/server/hosts.zh.md`) 的要求,修复了 `sb.sh` 脚本中 DNS 服务器配置的字段名错误。

---

## 🔍 问题分析

### 问题 1: DNS 服务器字段名不符合规范

**位置:**
- 第 1262-1265 行(初始配置生成)
- 第 3452-3455 行(DNS 解锁服务器配置生成)

**错误配置:**
```json
{
    "tag": "dns_block",
    "type": "hosts",
    "mapping": {}  // ❌ 错误:不符合 sing-box 1.12.0+ 规范
}
```

**官方文档要求:**
根据 `docs/configuration/dns/server/hosts.zh.md` 第 54-69 行:

```json
{
    "tag": "dns_block",
    "type": "hosts",
    "predefined": {}  // ✅ 正确:使用 "predefined" 字段
}
```

**影响:**
- 使用旧版字段名 `mapping` 可能导致配置无法被 sing-box 1.12.0+ 正确解析
- 可能导致 DNS 拦截功能失效

---

## ✅ 修复内容

### 修复 1: 初始配置生成中的字段名

**文件:** `sb.sh`  
**行号:** 1262-1265

**修改前:**
```bash
            {
                "tag": "dns_block",
                "type": "hosts",
                "mapping": {}
            }
```

**修改后:**
```bash
            {
                "tag": "dns_block",
                "type": "hosts",
                "predefined": {}
            }
```

### 修复 2: DNS 解锁服务器配置生成中的字段名

**文件:** `sb.sh`  
**行号:** 3452-3455

**修改前:**
```bash
      {
        "tag": "dns_block",
        "type": "hosts",
        "mapping": {}
      }
```

**修改后:**
```bash
      {
        "tag": "dns_block",
        "type": "hosts",
        "predefined": {}
      }
```

---

## 🎯 验证结果

### 1. 语法检查
```bash
bash -n sb.sh
```
**结果:** ✅ 通过,无语法错误

### 2. 配置合规性检查

根据官方文档验证:

| 配置项 | 修复前 | 修复后 | 状态 |
|--------|--------|--------|------|
| DNS 服务器字段名 | `mapping` | `predefined` | ✅ 合规 |
| DNS 规则 `rule_set` | 正确 | 正确 | ✅ 合规 |
| DNS 规则 `action` | 正确(默认) | 正确(默认) | ✅ 合规 |
| 规则集定义 | 正确 | 正确 | ✅ 合规 |
| `services.resolved` | 正确 | 正确 | ✅ 合规 |

### 3. 功能验证

**已验证的功能:**
- ✅ DNS 服务器配置生成
- ✅ DNS 规则集引用
- ✅ 远程规则集下载
- ✅ `resolved` 服务配置

---

## 📚 相关文档

### 官方文档参考

1. **DNS 服务器配置:**
   - `docs/configuration/dns/server/hosts.zh.md`
   - 说明了 `predefined` 字段的正确用法

2. **DNS 规则配置:**
   - `docs/configuration/dns/rule.zh.md`
   - 确认了 `rule_set` 字段的支持(自 sing-box 1.8.0 起)

3. **DNS 规则动作:**
   - `docs/configuration/dns/rule_action.zh.md`
   - 说明了 `action: "route"` 是默认值,可以省略

4. **Resolved 服务:**
   - `docs/configuration/service/resolved.zh.md`
   - 确认了 `services.resolved` 的正确配置方式

---

## 🔄 向后兼容性

### 影响范围
- **影响版本:** sing-box 1.12.0+
- **向后兼容:** 旧版本 sing-box 可能不支持 `predefined` 字段

### 建议
- 使用 sing-box 1.12.0 或更高版本
- 如果使用旧版本,建议升级到最新版本

---

## 📝 技术说明

### 为什么使用 `services.resolved` 而不是 `inbounds.direct`?

**`services.resolved` 的优势:**
1. ✅ 专门为 DNS 服务设计(自 sing-box 1.12.0 起)
2. ✅ 自动处理 DNS 查询并应用 DNS 规则
3. ✅ 支持 systemd-resolved DBUS 接口
4. ✅ 更简洁的配置

**`inbounds.direct` 的局限:**
1. ❌ 需要配合 `override_address` 和 `override_port` 使用
2. ❌ 主要用于流量转发,不是专门的 DNS 服务
3. ❌ 配置更复杂

**结论:**
对于纯 DNS 解锁服务器,使用 `services.resolved` 是最佳实践。

---

## 🚀 后续优化建议

### 1. 添加 DNS 规则动作的显式声明

虽然 `action: "route"` 是默认值,但为了代码可读性,建议显式声明:

```json
{
    "rule_set": ["geosite-netflix"],
    "action": "route",  // 显式声明
    "server": "dns_unlock_upstream",
    "strategy": "ipv6_only"
}
```

### 2. 添加 DNS 缓存配置

建议在 DNS 配置中添加缓存优化:

```json
{
    "dns": {
        "servers": [...],
        "rules": [...],
        "independent_cache": true,
        "cache_capacity": 10000  // 增加缓存容量
    }
}
```

### 3. 添加 DNS 查询日志

建议添加 DNS 查询日志以便调试:

```json
{
    "log": {
        "level": "debug",  // 开启调试日志
        "output": "/var/log/sing-box/dns-unlock.log"
    }
}
```

---

## ✅ 修复完成清单

- [x] 修复 DNS 服务器字段名错误(`mapping` → `predefined`)
- [x] 验证脚本语法正确性
- [x] 验证配置符合官方文档规范
- [x] 确认 `services.resolved` 配置正确
- [x] 创建修复报告文档

---

## 📞 联系方式

如有问题或建议,请在 GitHub 仓库提交 Issue:
https://github.com/lucking7/singshadowtls/issues

---

**修复完成时间:** 2025-10-30  
**修复人员:** AI Assistant  
**审核状态:** ✅ 已完成

