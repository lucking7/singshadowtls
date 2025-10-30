# Changelog - sb.sh v3.3

## [3.3] - 2025-10-30

### 🔧 修复 (Bug Fixes)

#### DNS 配置合规性修复

**问题描述:**
- DNS 服务器配置使用了不符合 sing-box 1.12.0+ 规范的字段名 `mapping`
- 应该使用官方文档要求的 `predefined` 字段

**修复内容:**
1. **修复位置 1:** 第 1262-1265 行(初始配置生成)
   - 修改前: `"mapping": {}`
   - 修改后: `"predefined": {}`

2. **修复位置 2:** 第 3452-3455 行(DNS 解锁服务器配置生成)
   - 修改前: `"mapping": {}`
   - 修改后: `"predefined": {}`

**影响范围:**
- 影响使用 sing-box 1.12.0+ 版本的用户
- 修复后配置完全符合官方文档规范

**参考文档:**
- `docs/configuration/dns/server/hosts.zh.md`

---

### 📚 文档更新 (Documentation)

**新增文档:**
- `BUGFIX_v3.3_DNS配置合规性修复.md` - 详细的修复报告
- `CHANGELOG_v3.3.md` - 本更新日志

---

### ✅ 验证 (Verification)

**语法检查:**
```bash
bash -n sb.sh
```
✅ 通过,无语法错误

**配置合规性:**
- ✅ DNS 服务器字段名符合规范
- ✅ DNS 规则配置正确
- ✅ 规则集引用正确
- ✅ `services.resolved` 配置正确

---

### 🔄 兼容性 (Compatibility)

**推荐版本:**
- sing-box >= 1.12.0

**向后兼容性:**
- 旧版本 sing-box 可能不支持 `predefined` 字段
- 建议升级到 sing-box 1.12.0 或更高版本

---

### 📝 技术细节 (Technical Details)

#### 修改的配置结构

**修改前:**
```json
{
    "dns": {
        "servers": [
            {
                "tag": "dns_block",
                "type": "hosts",
                "mapping": {}  // ❌ 不符合规范
            }
        ]
    }
}
```

**修改后:**
```json
{
    "dns": {
        "servers": [
            {
                "tag": "dns_block",
                "type": "hosts",
                "predefined": {}  // ✅ 符合规范
            }
        ]
    }
}
```

#### 官方文档说明

根据 `docs/configuration/dns/server/hosts.zh.md`:

```markdown
#### predefined

预定义的 hosts。

示例：

{
  "predefined": {
    "www.google.com": "127.0.0.1",
    "localhost": [
      "127.0.0.1",
      "::1"
    ]
  }
}
```

---

### 🎯 未来优化建议 (Future Improvements)

1. **显式声明 DNS 规则动作**
   - 虽然 `action: "route"` 是默认值,但建议显式声明以提高可读性

2. **优化 DNS 缓存配置**
   - 增加 `cache_capacity` 以提升性能

3. **添加 DNS 查询日志**
   - 便于调试和监控

---

### 📊 统计信息 (Statistics)

**修改文件:**
- `sb.sh` (2 处修改)

**新增文件:**
- `BUGFIX_v3.3_DNS配置合规性修复.md`
- `CHANGELOG_v3.3.md`

**代码行数变化:**
- 修改: 4 行
- 新增: 0 行
- 删除: 0 行

---

### 🔗 相关链接 (Related Links)

**GitHub 仓库:**
https://github.com/lucking7/singshadowtls

**问题反馈:**
https://github.com/lucking7/singshadowtls/issues

**官方文档:**
- [sing-box DNS 配置](https://sing-box.sagernet.org/zh/configuration/dns/)
- [sing-box Hosts DNS 服务器](https://sing-box.sagernet.org/zh/configuration/dns/server/hosts/)

---

### 👥 贡献者 (Contributors)

- AI Assistant - 代码修复和文档编写

---

### 📅 发布信息 (Release Information)

**发布日期:** 2025-10-30  
**版本号:** v3.3  
**上一版本:** v3.2  
**修复类型:** Bug Fix (配置合规性)

---

## [3.2] - 之前版本

详见之前的更新日志。

---

**注意:** 本次更新为配置合规性修复,不影响现有功能,建议所有用户更新。

