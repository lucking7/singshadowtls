# DNS 分流配置 jq 类型修复说明

## 问题描述

### 错误信息

```
正在应用 DNS 分流配置...
jq: error (at /etc/sing-box/config.json:288): string ("geosite-ca...) and array (["geoip-cn"...) cannot have their containment checked
```

### 错误原因

**根本原因：**
- jq 的 `contains()` 函数要求两边的操作数类型必须一致
- 在 sing-box 配置中，`rule_set` 字段可以是**字符串**或**数组**
- 原有代码假设 `rule_set` 总是数组，导致类型不匹配错误

**sing-box 规范：**
根据官方文档（`docs/configuration/dns/rule.md` 第 199 行）：

> **You can ignore the JSON Array [] tag when the content is only one item**

这意味着：
- ✅ `"rule_set": ["geosite-netflix"]` - 数组（单个元素）
- ✅ `"rule_set": "geosite-netflix"` - 字符串（简化写法）
- ✅ `"rule_set": ["geoip-cn", "geosite-cn"]` - 数组（多个元素）

**错误场景：**
```json
{
  "dns": {
    "rules": [
      {
        "rule_set": "geosite-category-ads-all",  // ← 字符串
        "server": "dns_block"
      },
      {
        "rule_set": ["geoip-cn", "geosite-cn"],  // ← 数组
        "server": "dns_local"
      }
    ]
  }
}
```

**原有 jq 命令（错误）：**
```jq
.dns.rules[] | select(.rule_set and (.rule_set | contains(["geosite-category-ads-all"])))
```

**问题：**
- 如果 `rule_set` 是字符串 `"geosite-category-ads-all"`
- jq 尝试执行：`"geosite-category-ads-all" | contains(["geosite-category-ads-all"])`
- 错误：字符串不能与数组进行 `contains()` 比较

---

## 修复方案

### 核心思路

**在使用 `contains()` 之前，先检查 `rule_set` 的类型：**
1. 如果是数组 → 使用 `contains()` 比较
2. 如果是字符串 → 使用 `==` 比较

### 修复位置

**文件：** `sb.sh`  
**函数：** `configure_dns_routing_rules`  
**行数：** 2850-2903（修复后）

---

## 修复前后对比

### 修复前（第 2860 行）

```jq
(.dns.rules[] | select(.rule_set and (.rule_set | contains(["geosite-category-ads-all"]))))
```

**问题：**
- ❌ 假设 `rule_set` 总是数组
- ❌ 如果 `rule_set` 是字符串，报错

---

### 修复后（第 2860-2864 行）

```jq
(.dns.rules[] | select(
    .rule_set and 
    ((.rule_set | type) == "array" and (.rule_set | contains(["geosite-category-ads-all"]))) or
    ((.rule_set | type) == "string" and .rule_set == "geosite-category-ads-all")
))
```

**改进：**
- ✅ 先检查类型：`(.rule_set | type) == "array"`
- ✅ 数组类型：使用 `contains(["geosite-category-ads-all"])`
- ✅ 字符串类型：使用 `.rule_set == "geosite-category-ads-all"`
- ✅ 使用 `or` 逻辑连接两种情况

---

### 修复前（第 2886 行）

```jq
(.dns.rules | map(select(.rule_set and (.rule_set | contains(["geoip-cn", "geosite-cn"])))))
```

**问题：**
- ❌ 假设 `rule_set` 总是数组
- ❌ 无法匹配字符串类型的 `"geoip-cn"` 或 `"geosite-cn"`

---

### 修复后（第 2890-2901 行）

```jq
(.dns.rules | map(select(
    .rule_set and (
        ((.rule_set | type) == "array" and (
            (.rule_set | contains(["geoip-cn"])) or 
            (.rule_set | contains(["geosite-cn"]))
        )) or
        ((.rule_set | type) == "string" and (
            .rule_set == "geoip-cn" or 
            .rule_set == "geosite-cn"
        ))
    )
)))
```

**改进：**
- ✅ 数组类型：检查是否包含 `"geoip-cn"` 或 `"geosite-cn"`
- ✅ 字符串类型：检查是否等于 `"geoip-cn"` 或 `"geosite-cn"`
- ✅ 覆盖所有可能的配置场景

---

## 完整修复代码

### 修复后的 jq 命令（第 2850-2903 行）

```bash
# 更新 DNS 规则
jq --arg netflix_srv "$netflix_server" \
   --arg disney_srv "$disney_server" \
   --arg spotify_srv "$spotify_server" \
   --arg youtube_srv "$youtube_server" \
   --arg other_srv "$other_server" \
   --arg netflix_st "$netflix_strat" \
   --arg disney_st "$disney_strat" \
   --arg other_st "$other_strat" \
   '.dns.rules = [
       (.dns.rules[] | select(
           .rule_set and 
           ((.rule_set | type) == "array" and (.rule_set | contains(["geosite-category-ads-all"]))) or
           ((.rule_set | type) == "string" and .rule_set == "geosite-category-ads-all")
       )),
       {
           "rule_set": ["geosite-netflix"],
           "server": $netflix_srv,
           "strategy": $netflix_st
       },
       {
           "rule_set": ["geosite-disney"],
           "server": $disney_srv,
           "strategy": $disney_st
       },
       {
           "rule_set": ["geosite-spotify"],
           "server": $spotify_srv,
           "strategy": "prefer_ipv4"
       },
       {
           "rule_set": ["geosite-youtube"],
           "server": $youtube_srv,
           "strategy": "prefer_ipv6"
       },
       {
           "rule_set": ["geosite-category-media"],
           "server": $other_srv,
           "strategy": $other_st
       }
   ] + (.dns.rules | map(select(
       .rule_set and (
           ((.rule_set | type) == "array" and (
               (.rule_set | contains(["geoip-cn"])) or 
               (.rule_set | contains(["geosite-cn"]))
           )) or
           ((.rule_set | type) == "string" and (
               .rule_set == "geoip-cn" or 
               .rule_set == "geosite-cn"
           ))
       )
   )))
   + [{"server": "dns_google", "strategy": "prefer_ipv4"}]' \
   /etc/sing-box/config.json > /tmp/config_temp.json && mv /tmp/config_temp.json /etc/sing-box/config.json
```

---

## 测试验证

### 测试用例 1: 字符串类型的 rule_set

**输入配置：**
```json
{
  "dns": {
    "rules": [
      {
        "rule_set": "geosite-category-ads-all",
        "server": "dns_block"
      },
      {
        "rule_set": "geoip-cn",
        "server": "dns_local"
      }
    ]
  }
}
```

**预期结果：**
- ✅ 保留 `geosite-category-ads-all` 规则
- ✅ 保留 `geoip-cn` 规则
- ✅ 添加流媒体规则
- ✅ 不报错

---

### 测试用例 2: 数组类型的 rule_set

**输入配置：**
```json
{
  "dns": {
    "rules": [
      {
        "rule_set": ["geosite-category-ads-all"],
        "server": "dns_block"
      },
      {
        "rule_set": ["geoip-cn", "geosite-cn"],
        "server": "dns_local"
      }
    ]
  }
}
```

**预期结果：**
- ✅ 保留 `geosite-category-ads-all` 规则
- ✅ 保留 `geoip-cn` 和 `geosite-cn` 规则
- ✅ 添加流媒体规则
- ✅ 不报错

---

### 测试用例 3: 混合类型的 rule_set

**输入配置：**
```json
{
  "dns": {
    "rules": [
      {
        "rule_set": "geosite-category-ads-all",
        "server": "dns_block"
      },
      {
        "rule_set": ["geoip-cn", "geosite-cn"],
        "server": "dns_local"
      },
      {
        "rule_set": "geosite-cn",
        "server": "dns_local"
      }
    ]
  }
}
```

**预期结果：**
- ✅ 保留所有匹配的规则
- ✅ 正确处理字符串和数组类型
- ✅ 不报错

---

## 技术细节

### jq 类型检查

**语法：** `(.rule_set | type)`

**返回值：**
- `"string"` - 字符串类型
- `"array"` - 数组类型
- `"object"` - 对象类型
- `"number"` - 数字类型
- `"boolean"` - 布尔类型
- `"null"` - 空值

---

### jq 逻辑运算符

**AND 运算符：** `and`
```jq
.rule_set and (.rule_set | type) == "array"
```

**OR 运算符：** `or`
```jq
(condition1) or (condition2)
```

---

### jq contains() 函数

**用法：** `array1 | contains(array2)`

**要求：**
- 两边必须是相同类型
- 数组与数组比较：检查 `array1` 是否包含 `array2` 的所有元素
- 字符串与字符串比较：检查 `string1` 是否包含 `string2`

**错误示例：**
```jq
"string" | contains(["array"])  # ❌ 类型不匹配
```

**正确示例：**
```jq
["a", "b"] | contains(["a"])    # ✅ true
"hello" | contains("ell")       # ✅ true
```

---

## 兼容性

### sing-box 版本兼容性

- ✅ **sing-box 1.8.0+** - 支持 `rule_set` 字段
- ✅ **sing-box 1.9.0+** - 支持字符串和数组类型
- ✅ **sing-box 1.12.0+** - 当前版本

### 配置兼容性

- ✅ **字符串类型** - `"rule_set": "geosite-cn"`
- ✅ **数组类型（单元素）** - `"rule_set": ["geosite-cn"]`
- ✅ **数组类型（多元素）** - `"rule_set": ["geoip-cn", "geosite-cn"]`
- ✅ **混合配置** - 同一配置文件中包含字符串和数组类型

---

## 总结

### 问题根源

1. ✅ sing-box 允许 `rule_set` 字段为字符串或数组
2. ✅ 原有 jq 命令假设 `rule_set` 总是数组
3. ✅ `contains()` 函数要求类型一致，导致报错

### 修复方案

1. ✅ 使用 `(.rule_set | type)` 检查类型
2. ✅ 数组类型使用 `contains()` 比较
3. ✅ 字符串类型使用 `==` 比较
4. ✅ 使用 `or` 逻辑连接两种情况

### 修复效果

- ✅ 支持字符串类型的 `rule_set`
- ✅ 支持数组类型的 `rule_set`
- ✅ 支持混合类型的配置
- ✅ 完全向后兼容
- ✅ 不再报类型不匹配错误

---

**修复完成！** 🎉

DNS 分流配置现在可以正确处理字符串和数组类型的 `rule_set` 字段，不会再出现 jq 类型不匹配错误。

