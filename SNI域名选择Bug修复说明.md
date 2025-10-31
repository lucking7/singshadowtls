# SNI 域名选择 Bug 修复说明

## 问题描述

### 错误信息
```bash
/dev/fd/63: line 1046: choice_to_domain: bad array subscript
/dev/fd/63: line 1046: choice_to_domain[$sni_choice]: unbound variable
```

### 错误场景

**触发条件：**
- 用户在 ShadowTLS SNI 域名选择步骤**直接按回车**（空输入）
- 或者输入**无效的选项**（如字母、超出范围的数字）

**错误位置：**
- 第 1046 行（修复前）：`[[ -n "${choice_to_domain[$sni_choice]}" ]]`

---

## 根本原因

### 1. Bash 严格模式

脚本第 4 行设置了：
```bash
set -uo pipefail
```

其中 `-u` 选项的作用：
- **检测未绑定变量**：访问未定义的变量时立即报错退出
- **关联数组访问**：访问不存在的键也会触发错误

### 2. 空输入导致的问题

**用户输入流程：**
```bash
read -p "Enter your choice [1-14] (Default: 1 - p11.douyinpic.com): " sni_choice
```

**问题分析：**
1. 用户直接按回车 → `$sni_choice` = `""` (空字符串)
2. 执行 `${choice_to_domain[$sni_choice]}` → `${choice_to_domain[]}` 
3. 关联数组访问空键 → 触发 "bad array subscript" 错误
4. 由于 `set -u` → 脚本立即退出

### 3. 无效输入导致的问题

**用户输入无效值：**
- 输入字母（如 `a`）
- 输入超出范围的数字（如 `99`）

**问题分析：**
1. `$sni_choice` = `"a"` 或 `"99"`
2. 执行 `${choice_to_domain[a]}` 或 `${choice_to_domain[99]}`
3. 数组中不存在该键 → 触发 "unbound variable" 错误
4. 由于 `set -u` → 脚本立即退出

---

## 修复方案

### 核心修复逻辑

**修复前（第 1031-1051 行）：**
```bash
read -p "..." sni_choice

if [[ "$sni_choice" == "$menu_index" ]]; then
    # Custom domain
    ...
elif [[ -n "${choice_to_domain[$sni_choice]}" ]]; then  # ❌ 问题行
    proxysite="${choice_to_domain[$sni_choice]}"
else
    # Invalid choice or empty, use default
    proxysite="$default_domain"
fi
```

**修复后（第 1031-1058 行）：**
```bash
read -p "..." sni_choice

# ✅ 1. 先处理空输入
if [[ -z "$sni_choice" ]]; then
    sni_choice=1
fi

if [[ "$sni_choice" == "$menu_index" ]]; then
    # Custom domain
    ...
elif [[ -n "$sni_choice" ]] && [[ -n "${choice_to_domain[$sni_choice]:-}" ]]; then  # ✅ 2. 安全访问数组
    # Valid choice from menu
    proxysite="${choice_to_domain[$sni_choice]}"
else
    # ✅ 3. 处理无效输入
    echo -e "${YELLOW}Invalid choice. Using default domain.${NC}"
    proxysite="$default_domain"
fi
```

---

## 修复要点

### 1. 空输入处理 ✅

**新增代码（第 1033-1036 行）：**
```bash
# Handle empty input (default to first domain)
if [[ -z "$sni_choice" ]]; then
    sni_choice=1
fi
```

**作用：**
- 用户直接按回车时，自动设置为选项 1（第一个有效域名）
- 避免空字符串访问数组

---

### 2. 安全的数组访问 ✅

**修改代码（第 1051 行）：**
```bash
# 修复前
elif [[ -n "${choice_to_domain[$sni_choice]}" ]]; then

# 修复后
elif [[ -n "$sni_choice" ]] && [[ -n "${choice_to_domain[$sni_choice]:-}" ]]; then
```

**关键改进：**

#### a) 先检查变量非空
```bash
[[ -n "$sni_choice" ]]
```
- 确保 `$sni_choice` 不是空字符串
- 避免访问 `${choice_to_domain[]}`

#### b) 使用参数扩展默认值
```bash
${choice_to_domain[$sni_choice]:-}
```
- `:-` 语法：如果键不存在，返回空字符串而不是报错
- 兼容 `set -u` 模式
- 即使键不存在，也不会触发 "unbound variable" 错误

---

### 3. 无效输入提示 ✅

**新增代码（第 1054-1058 行）：**
```bash
else
    # Invalid choice, use default
    echo -e "${YELLOW}Invalid choice. Using default domain.${NC}"
    proxysite="$default_domain"
fi
```

**改进：**
- 明确提示用户输入无效
- 自动使用默认域名
- 不会中断脚本执行

---

## 测试场景

### 场景 1: 空输入（直接按回车）

**输入：**
```
Enter your choice [1-14] (Default: 1 - p11.douyinpic.com): [回车]
```

**预期行为：**
- ✅ 自动选择选项 1
- ✅ 使用第一个有效域名
- ✅ 显示：`Using SNI: p11.douyinpic.com`

---

### 场景 2: 有效输入（选择菜单选项）

**输入：**
```
Enter your choice [1-14] (Default: 1 - p11.douyinpic.com): 3
```

**预期行为：**
- ✅ 选择第 3 个域名
- ✅ 从 `choice_to_domain[3]` 获取域名
- ✅ 显示：`Using SNI: coding.net`

---

### 场景 3: 自定义域名（选择最后一个选项）

**输入：**
```
Enter your choice [1-14] (Default: 1 - p11.douyinpic.com): 14
Enter custom domain: example.com
```

**预期行为：**
- ✅ 进入自定义域名流程
- ✅ 验证 TLS 1.3 支持
- ✅ 显示：`Using SNI: example.com`

---

### 场景 4: 无效输入（字母）

**输入：**
```
Enter your choice [1-14] (Default: 1 - p11.douyinpic.com): abc
```

**预期行为：**
- ✅ 显示：`Invalid choice. Using default domain.`
- ✅ 使用默认域名：`p11.douyinpic.com`
- ✅ 继续执行，不报错退出

---

### 场景 5: 无效输入（超出范围）

**输入：**
```
Enter your choice [1-14] (Default: 1 - p11.douyinpic.com): 99
```

**预期行为：**
- ✅ 显示：`Invalid choice. Using default domain.`
- ✅ 使用默认域名：`p11.douyinpic.com`
- ✅ 继续执行，不报错退出

---

## 技术细节

### Bash 参数扩展语法

#### `${parameter:-word}`
- **作用：** 如果 `parameter` 未设置或为空，返回 `word`
- **用途：** 提供默认值，避免 `set -u` 报错

#### `${array[key]:-}`
- **作用：** 如果 `array[key]` 不存在，返回空字符串
- **用途：** 安全访问关联数组，兼容 `set -u`

**示例：**
```bash
declare -A my_array=([1]="value1" [2]="value2")

# ❌ 错误：set -u 模式下会报错
echo "${my_array[3]}"  # unbound variable

# ✅ 正确：返回空字符串
echo "${my_array[3]:-}"  # 输出空行

# ✅ 正确：返回默认值
echo "${my_array[3]:-default}"  # 输出 "default"
```

---

### 关联数组访问规则

**Bash 关联数组特性：**
1. 键不存在时，访问会触发错误（`set -u` 模式）
2. 空字符串作为键是合法的，但容易引起混淆
3. 必须先检查键是否存在，再访问值

**最佳实践：**
```bash
# ❌ 不安全
if [[ -n "${array[$key]}" ]]; then
    value="${array[$key]}"
fi

# ✅ 安全（方法 1：使用 :- 默认值）
if [[ -n "${array[$key]:-}" ]]; then
    value="${array[$key]}"
fi

# ✅ 安全（方法 2：先检查变量）
if [[ -n "$key" ]] && [[ -n "${array[$key]:-}" ]]; then
    value="${array[$key]}"
fi
```

---

## 影响范围

### 修改文件
- `sb.sh` - 第 1031-1058 行

### 修改内容
- ✅ 新增空输入处理（4 行）
- ✅ 修改数组访问逻辑（1 行）
- ✅ 新增无效输入提示（1 行）

### 兼容性
- ✅ 向后兼容：不影响现有正确输入
- ✅ 错误处理：优雅处理所有边界情况
- ✅ 用户体验：提供清晰的错误提示

---

## 总结

### 问题根源
1. ✅ `set -u` 严格模式检测未绑定变量
2. ✅ 空输入导致访问 `${choice_to_domain[]}`
3. ✅ 无效输入导致访问不存在的数组键

### 修复方案
1. ✅ 空输入自动设置为选项 1
2. ✅ 使用 `${array[$key]:-}` 安全访问数组
3. ✅ 先检查变量非空，再访问数组
4. ✅ 无效输入显示提示并使用默认值

### 测试覆盖
- ✅ 空输入（直接按回车）
- ✅ 有效输入（1-13）
- ✅ 自定义域名（14）
- ✅ 无效输入（字母、超出范围）

---

**修复完成！** 🎉

现在脚本可以正确处理所有 SNI 域名选择场景，不会因为空输入或无效输入而报错退出。

