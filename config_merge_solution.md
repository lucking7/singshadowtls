# Sing-Box 配置合并方案

## 问题描述

当前 sb.sh 脚本存在配置覆盖问题：
- 代理配置（选项 1-12）会覆盖整个配置文件
- DNS 解锁配置（选项 13）会覆盖整个配置文件

如果用户想要在同一台机器上同时运行：
1. Sing-Box 代理服务器（Shadowsocks/ShadowTLS）
2. DNS 解锁客户端（连接解锁机的 SmartDNS）

则会出现配置丢失问题。

## 解决方案

### 方案 1：配置检测与合并（推荐）

#### 实现思路

1. **在配置 DNS 解锁前检测现有配置**
   - 检查是否存在 inbounds（代理入站）
   - 检查是否存在 outbounds（代理出站）
   - 如果存在，则进行合并而不是覆盖

2. **配置合并逻辑**
   ```bash
   if 现有配置包含代理; then
       # 保留 inbounds 和 outbounds
       # 添加/更新 DNS 配置
       # 合并到新配置
   else
       # 生成纯 DNS 配置
   fi
   ```

3. **添加配置模式选择**
   ```
   当前检测到您已配置代理服务，请选择：
   1) 仅 DNS 解锁（清除代理配置）
   2) 代理 + DNS 解锁（合并配置）
   3) 取消操作
   ```

#### 配置结构示例

**合并后的配置**：
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
        "domain_suffix": [".netflix.com"],
        "server": "unlock_dns"
      },
      {
        "domain": ["geosite:category-media"],
        "server": "unlock_dns"
      }
    ]
  },
  "inbounds": [
    {
      "type": "shadowsocks",
      "listen": "::",
      "listen_port": 8388,
      ...
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": []
  }
}
```

### 方案 2：配置模板系统

创建预定义的配置模板：
- `proxy_only.json` - 仅代理
- `dns_only.json` - 仅 DNS
- `proxy_dns.json` - 代理 + DNS

用户安装时选择模板。

### 方案 3：配置片段系统

将配置拆分为独立片段：
- `/etc/sing-box/conf.d/proxy.json` - 代理配置
- `/etc/sing-box/conf.d/dns.json` - DNS 配置

启动时合并所有片段（需要额外脚本）。

## 推荐实现：方案 1

### 实现步骤

#### 步骤 1：添加配置检测函数

```bash
# 检测现有配置类型
detect_config_type() {
    local config_file="/etc/sing-box/config.json"

    if [[ ! -f "$config_file" ]]; then
        echo "none"
        return
    fi

    local has_inbounds=$(jq -e '.inbounds // empty' "$config_file" 2>/dev/null)
    local has_dns=$(jq -e '.dns // empty' "$config_file" 2>/dev/null)

    if [[ -n "$has_inbounds" && -n "$has_dns" ]]; then
        echo "proxy_dns"
    elif [[ -n "$has_inbounds" ]]; then
        echo "proxy"
    elif [[ -n "$has_dns" ]]; then
        echo "dns"
    else
        echo "unknown"
    fi
}
```

#### 步骤 2：添加配置合并函数

```bash
# 合并代理配置和 DNS 配置
merge_proxy_dns_config() {
    local current_config="/etc/sing-box/config.json"
    local backup_config="/etc/sing-box/config.json.merge_backup"

    # 备份现有配置
    cp "$current_config" "$backup_config"

    # 提取现有的 inbounds 和 outbounds
    local inbounds=$(jq '.inbounds' "$backup_config")
    local outbounds=$(jq '.outbounds' "$backup_config")
    local route=$(jq '.route // {}' "$backup_config")

    # 生成新的 DNS 配置（当前 deploy_dns_unlock_client 的逻辑）
    # ... DNS 配置生成逻辑 ...

    # 合并配置
    jq --argjson inbounds "$inbounds" \
       --argjson outbounds "$outbounds" \
       --argjson route "$route" \
       '. + {
           inbounds: $inbounds,
           outbounds: $outbounds,
           route: $route
       }' "$current_config" > "$current_config.tmp"

    mv "$current_config.tmp" "$current_config"
}
```

#### 步骤 3：修改 deploy_dns_unlock_client 函数

在函数开始处添加配置类型检测：

```bash
deploy_dns_unlock_client() {
    echo -e "\n${CYAN}检测现有配置...${NC}"

    local config_type=$(detect_config_type)

    case "$config_type" in
        "proxy")
            echo -e "${YELLOW}检测到您已配置代理服务${NC}\n"
            echo -e "${YELLOW}请选择操作模式:${NC}"
            echo -e "  ${CYAN}1)${NC} 仅 DNS 解锁 ${RED}(将清除代理配置)${NC}"
            echo -e "  ${CYAN}2)${NC} 代理 + DNS 解锁 ${GREEN}(推荐)${NC}"
            echo -e "  ${CYAN}0)${NC} 取消操作\n"

            read -p "请选择 [0-2]: " mode_choice

            case "$mode_choice" in
                1)
                    echo -e "${YELLOW}警告: 将清除现有代理配置${NC}"
                    confirm_action "确认清除代理配置？" "n" || return 1
                    # 继续正常的 DNS 配置流程
                    ;;
                2)
                    echo -e "${GREEN}将合并代理和 DNS 配置${NC}"
                    # 调用合并函数
                    merge_mode=true
                    ;;
                0)
                    return 0
                    ;;
                *)
                    echo -e "${RED}无效选择${NC}"
                    return 1
                    ;;
            esac
            ;;
        "dns")
            echo -e "${YELLOW}检测到您已配置 DNS 解锁${NC}"
            echo -e "${YELLOW}将更新 DNS 配置${NC}\n"
            ;;
        "proxy_dns")
            echo -e "${YELLOW}检测到您已配置代理 + DNS 解锁${NC}"
            echo -e "${YELLOW}将更新 DNS 配置，保留代理设置${NC}\n"
            merge_mode=true
            ;;
        "none")
            echo -e "${GREEN}首次配置 DNS 解锁${NC}\n"
            ;;
    esac

    # 根据 merge_mode 决定使用合并还是覆盖
    if [[ "$merge_mode" == true ]]; then
        merge_proxy_dns_config
    else
        # 原有的覆盖逻辑
        cat > /etc/sing-box/config.json << 'EOFCONFIG'
        ...
    fi
}
```

## 使用示例

### 场景 1：先安装代理，后添加 DNS 解锁

```bash
# 步骤 1: 安装代理
sudo bash sb.sh
# 选择: 1) Install Sing-Box (Beta)
# 选择: 安装模式（如 Shadowsocks）
# ✓ 代理配置完成

# 步骤 2: 添加 DNS 解锁
sudo bash sb.sh
# 选择: 13) DNS 分流客户端 (被解锁机)
# 选择: 1) 部署 DNS 分流客户端
# 检测到代理配置
# 选择: 2) 代理 + DNS 解锁 (推荐)
# ✓ 配置合并完成

# 结果：同时拥有代理和 DNS 解锁功能
```

### 场景 2：一键配置代理 + DNS 解锁

可以考虑添加新选项：

```
主菜单新增选项:
20) 安装代理 + DNS 解锁 (一键配置)
```

## 注意事项

### 配置兼容性

合并配置时需要注意：
1. **DNS 出站路由**: DNS 查询需要通过 direct 出站
2. **日志配置**: 合并时保留原有日志设置
3. **监听地址**: 确保端口不冲突
   - 代理：如 8388、443
   - DNS：127.0.0.1:53

### 测试建议

1. **单独测试**
   - 仅代理配置
   - 仅 DNS 配置

2. **合并测试**
   - 先代理后 DNS
   - 先 DNS 后代理（需要额外实现）

3. **功能验证**
   - 代理连接测试
   - DNS 解析测试
   - 流媒体访问测试

## 实施优先级

### 高优先级（必须实现）
- ✅ 配置类型检测
- ✅ 用户提示和选择
- ✅ 配置合并逻辑

### 中优先级（建议实现）
- ⏳ 配置备份和恢复
- ⏳ 配置 Diff 预览
- ⏳ 一键安装选项

### 低优先级（可选）
- ⏳ 配置模板系统
- ⏳ 配置片段系统
- ⏳ 图形化配置界面

## 参考配置

完整的合并配置示例见附件：`example_merged_config.json`

## 总结

配置合并方案能够完美解决代理和 DNS 解锁共存的问题，同时保持向后兼容性。建议优先实现方案 1 的核心功能。
