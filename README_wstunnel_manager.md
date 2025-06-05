# wstunnel 管理工具

一个功能完善的 wstunnel 管理脚本，支持 TCP/UDP 转发、SOCKS5 代理等功能，并提供友好的交互式菜单界面。

## 功能特点

- 🖥️ **交互式菜单界面** - 简单易用的菜单系统
- 🌐 **IP信息显示** - 显示本机IPv4/IPv6地址和公网IP的ASN/ORG信息
- 🔄 **多种转发模式** - 支持TCP、UDP端口转发，SOCKS5、HTTP代理，透明代理
- 🌍 **双栈支持** - 完整支持IPv4和IPv6
- 🔧 **服务管理** - 使用systemd管理服务，支持开机自启
- 📝 **配置持久化** - 所有配置保存在JSON文件中
- 🚀 **自动安装** - 自动下载并安装最新版本的wstunnel

## 系统要求

- Ubuntu/Debian 系统
- 需要sudo权限（脚本会在需要时自动请求）
- 支持的架构：x86_64, aarch64, armv7

## 安装和使用

1. 下载脚本：
```bash
wget https://raw.githubusercontent.com/your-repo/wstunnel_manager.sh
# 或
curl -O https://raw.githubusercontent.com/your-repo/wstunnel_manager.sh
```

2. 添加执行权限：
```bash
chmod +x wstunnel_manager.sh
```

3. 运行脚本：
```bash
./wstunnel_manager.sh
```

## 菜单功能说明

### 1. 显示本机IP信息
- 显示所有本地IPv4和IPv6地址
- 显示公网IP地址
- 显示ASN/ORG信息（ISP信息）
- 显示地理位置信息

### 2. 安装/更新 wstunnel
- 自动检测系统架构
- 下载对应的二进制文件
- 安装到 `/usr/local/bin/wstunnel`

### 3. 配置客户端
支持以下隧道类型：
- **TCP端口转发** - 将本地TCP端口转发到远程主机
- **UDP端口转发** - 将本地UDP端口转发到远程主机
- **SOCKS5代理** - 创建SOCKS5代理服务器
- **HTTP代理** - 创建HTTP代理服务器
- **透明代理** - 创建透明代理（需要root权限）

高级选项：
- 连接池配置
- HTTP代理设置
- 自定义SNI域名

### 4. 配置服务器
- 支持WebSocket (ws://) 和 WebSocket Secure (wss://)
- 可选择监听地址（IPv4/IPv6）
- TLS证书配置（内置自签名或自定义证书）
- 访问控制（限制可访问的目标）
- HTTP升级路径前缀（用作认证密钥）

### 5. 管理服务
- 查看所有服务状态
- 启动/停止/重启服务
- 查看服务状态和日志
- 启用/禁用开机自启
- 删除配置

### 6. 查看所有配置
- 列出所有已保存的配置
- 显示配置类型和创建时间

### 7. 使用示例
- 提供常见使用场景的示例命令

## 使用示例

### 示例1：TCP端口转发
将本地8080端口的流量转发到远程服务器的80端口：
1. 运行脚本，选择"3) 配置客户端"
2. 输入配置名称：`web-forward`
3. 选择监听地址类型：`1) IPv4 (127.0.0.1)`
4. 选择隧道类型：`1) TCP端口转发`
5. 本地端口：`8080`
6. 远程主机：`example.com`
7. 远程端口：`80`
8. 输入服务器地址：`wss://your-wstunnel-server.com:443`

### 示例2：SOCKS5代理
创建一个SOCKS5代理用于浏览器：
1. 运行脚本，选择"3) 配置客户端"
2. 输入配置名称：`socks-proxy`
3. 选择监听地址类型：`1) IPv4 (127.0.0.1)`
4. 选择隧道类型：`3) SOCKS5代理`
5. 本地端口：`1080`
6. 输入服务器地址：`wss://your-wstunnel-server.com:443`

### 示例3：设置服务器
在服务器上设置wstunnel服务：
1. 运行脚本，选择"4) 配置服务器"
2. 输入配置名称：`main-server`
3. 选择监听地址类型：`2) 所有接口 IPv6 ([::])`
4. 监听端口：`443`
5. 选择协议：`2) WebSocket Secure (wss://)`
6. TLS证书配置：选择合适的选项

## 配置文件位置

- 主配置文件：`/etc/wstunnel/config.json`
- 日志文件：`/var/log/wstunnel/`
- systemd服务文件：`/etc/systemd/system/wstunnel-*.service`

## 常用命令

查看服务状态：
```bash
sudo systemctl status wstunnel-配置名称
```

查看服务日志：
```bash
sudo journalctl -u wstunnel-配置名称 -f
```

手动启动服务：
```bash
sudo systemctl start wstunnel-配置名称
```

## 注意事项

1. **不要以root身份运行脚本** - 脚本会在需要时自动请求sudo权限
2. **防火墙配置** - 确保相应的端口已在防火墙中开放
3. **透明代理** - 需要额外配置iptables规则
4. **性能优化** - 对于高并发场景，建议启用连接池功能

## 故障排除

1. **无法连接到服务器**
   - 检查服务器地址是否正确
   - 确认防火墙规则
   - 查看日志文件

2. **服务无法启动**
   - 检查端口是否被占用
   - 查看systemd日志：`sudo journalctl -xe`

3. **性能问题**
   - 启用连接池功能
   - 调整UDP超时时间
   - 检查网络延迟

## 安全建议

1. 使用wss://（TLS加密）而不是ws://
2. 设置HTTP升级路径前缀作为认证密钥
3. 限制服务器可访问的目标地址
4. 使用有效的TLS证书（如Let's Encrypt）
5. 定期更新wstunnel到最新版本

## 相关链接

- wstunnel官方仓库：https://github.com/erebe/wstunnel
- wstunnel文档：https://github.com/erebe/wstunnel#readme

## 许可证

此脚本遵循MIT许可证。wstunnel本身遵循BSD-3-Clause许可证。