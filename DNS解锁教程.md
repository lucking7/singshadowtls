# DNS 解锁教程：自建流媒体解锁服务

## 写在前面

为实现自建 DNS 解锁可以采取两种办法：第一种直接在被解锁服务器设置解锁，适用于单个服务器需要解锁的应用场景。第二种建立私人 DNS 服务器，适用于多台服务器需要解锁的应用场景。

| 对比项目         | 方案一                             | 方案二                             |
| ---------------- | ---------------------------------- | ---------------------------------- |
| 搭建 sni 代理    | √                                  | √                                  |
| 搭建 DNS 服务器  | √                                  | ×                                  |
| 被解锁机本地设置 | 仅需修改系统 DNS                   | 需要在所有被解锁机搭建 smartdns    |
| 灵活性           | 快捷                               | 较为复杂                           |
| 可靠性           | 自建 DNS 服务器宕机，本地 DNS 瘫痪 | 自建 DNS 服务器宕机，本地 DNS 正常 |
| 应用场景         | 多台服务器                         | 单台服务器                         |

本文之所以选择用 smartdns 取代 Dnsmasq，在于 smartdns 无论是在查询速度、查询到的 IP 访问速度和广告过滤都强于 Dnsmasq。

## 必备内容

- 1 台解锁流媒体的服务器（443 和 80 端口不能被占用）

## 搭建教程

由于存在两种实现方法，教程除了 sni 代理为统一步骤外，其余部分因差异性将分开阐述。

### 安装 SNI Proxy

```bash
wget --no-check-certificate -O dnsmasq_sniproxy.sh https://raw.githubusercontent.com/myxuchangbin/dnsmasq_sniproxy_install/master/dnsmasq_sniproxy.sh && bash dnsmasq_sniproxy.sh -is
```

### 设置 SNI Proxy

修改配置文件，将所需 dns 解锁的网址格式化输入

`/etc/sniproxy.conf`

格式示例：

```
user daemon
pidfile /var/tmp/sniproxy.pid

error_log {
    syslog daemon
    priority notice
}

resolver {
    nameserver 8.8.8.8
    nameserver 8.8.4.4 # local dns should be better
    mode ipv4_only
}

listener 0.0.0.0:80 {
    proto http
    access_log {
        filename /var/log/sniproxy/http_access.log
        priority notice
    }
}

listener 0.0.0.0:443 {
    proto tls
    access_log {
        filename /var/log/sniproxy/https_access.log
        priority notice
    }
}

table {
    .*ai\.com$ *
    .*openai\.com$ *
    .*chatgpt.com$ *
    .*oaistatic.com$ *
    .*oaiusercontent.com$ *
}
```

### 重启 SNI Proxy

```bash
systemctl restart sniproxy
```

### 解锁机设置解锁白名单

如未安装 ufw，请先执行

```bash
sudo apt install ufw
ufw enable
```

第一次安装一定要放行当前使用的 ssh 端口

```bash
sudo ufw allow 22/tcp
```

修改下面示例的 IP（写被解锁机 IP），执行即可。

```bash
sudo ufw allow from 2.2.2.2 to any port 443 proto tcp
sudo ufw allow from 2.2.2.2 to any port 443 proto udp
sudo ufw allow from 2.2.2.2 to any port 80 proto tcp
sudo ufw allow from 2.2.2.2 to any port 80 proto udp
```

## 方案一：安装 smartdns 搭建 DNS 服务器

此处可以用另一台服务器，也可以就用搭建 sni 代理那台服务器。

```bash
wget https://github.com/pymumu/smartdns/releases/download/Release46/smartdns.1.2024.06.12-2222.x86-linux-all.tar.gz
tar zxf smartdns.1.2024.06.12-2222.x86-linux-all.tar.gz
cd smartdns
chmod +x ./install
./install -i
```

### 设置 smardns

```bash
vi /etc/smartdns/smartdns.conf
```

编辑配置，自行添加需要解锁的网址，常见流媒体域名可以参考 1stream 写好的。

格式示例：

```
bind[::]:53@eth0 -no-dualstack-selection -no-speed-check #不要动
dualstack-ip-selection no
speed-check-mode none
serve-expired-prefetch-time 21600
prefetch-domain yes
cache-size 32768
cache-persist yes
cache-file /etc/smartdns/cache
prefetch-domain yes
serve-expired yes
serve-expired-ttl 259200
serve-expired-reply-ttl 3
prefetch-domain yes
serve-expired-prefetch-time 21600
cache-checkpoint-time 86400
#force-AAAA-SOA yes
server 210.0.255.250 #默认上游DNS
server 210.0.255.251 #默认上游DNS

# ---------- > Global Plaform
# > GPT
address /openai.com/解锁机IP
address /chatgpt.com/解锁机IP
address /oaistatic.com/解锁机IP
address /oaiusercontent.com/解锁机IP
```

保存并启动

```bash
systemctl enable smartdns
systemctl start smartdns
```

### DNS 服务器开启 DNS 白名单

强烈建议开启 DNS 白名单，不开启会被别人白嫖，也可能被 D 哥用作 DNS 放大攻击
开启白名单

修改下面示例的 IP 即可。

```bash
ufw allow from 2.2.2.2 to any port 53 proto udp
```

### 被解锁服务器修改 DNS

修改 DNS 为解锁机或者 DNS 服务器的 IP。

```bash
vim /etc/resolv.conf
```

## 方案二

在被解锁服务器本地搭建 smartdns

安装步骤和方案一相同，此处不再赘述。

配置文件有所改变，具体改动为第一行的 DNS 设置，该设置限制了仅本地可以访问
格式示例：

```
bind :53@lo -no-dualstack-selection -no-speed-check #不要动
dualstack-ip-selection no
speed-check-mode none
serve-expired-prefetch-time 21600
prefetch-domain yes
cache-size 32768
cache-persist yes
cache-file /etc/smartdns/cache
prefetch-domain yes
serve-expired yes
serve-expired-ttl 259200
serve-expired-reply-ttl 3
prefetch-domain yes
serve-expired-prefetch-time 21600
cache-checkpoint-time 86400
#force-AAAA-SOA yes
server 210.0.255.250 #默认上游DNS
server 210.0.255.251 #默认上游DNS


# ---------- > Global Plaform
# > GPT
address /openai.com/解锁机IP
address /chatgpt.com/解锁机IP
address /oaistatic.com/解锁机IP
address /oaiusercontent.com/解锁机IP
```

### 被解锁服务器修改 DNS

修改 DNS 为 127.0.0.1

```bash
vim /etc/resolv.conf
```

## 高级玩法

### 玩法一 嵌套解锁

其实，在某些商家提供 DNS 解锁的服务器也可以利用本教程给其他服务器提供解锁，就是嵌套解锁（该行为可能违反 TOS）。
借助方案一，使用自建 DNS，只需要改一下上游 DNS 设置和域名对应的 DNS 设置即可实现。

```
server 210.0.255.250 #默认上游DNS
server 210.0.255.251 #默认上游DNS
server 此处写商家提供的DNS IP -group dnsproxy -exclude-default-group

# > Netflix
nameserver /netflix.com/dnsproxy
nameserver /netflix.net/dnsproxy
nameserver /nflximg.com/dnsproxy
nameserver /nflximg.net/dnsproxy
nameserver /nflxvideo.net/dnsproxy
nameserver /nflxext.com/dnsproxy
nameserver /nflxso.net/dnsproxy
```

### 玩法二 自建 DOH 服务器

某些厂商强制劫持了 53 端口的 UDP 流量，导致无论怎么改 DNS 都无法摆脱商家的解锁服务，此时 DOH 就派上了用处。
DOH 简单说就是 DNS over HTTPS，通过 DOH 走 TCP 流量使用 TLS 可以完美绕过 DNS 劫持。
smartdns 可以搭建 DOH 服务器，但是我没搭建成功，so sad。所以仅介绍 adguardhome 搭建 DOH。
具体 adguardhome 搭建 DOH 的教程网络已有很多，此处就省去了。搭建过程中，唯一需要注意的是，上游 DNS 需要写 127.0.0.1。
被 DNS 劫持的服务器只需要在 smartdns 中将默认 DNS 设置为自己刚建好的 DOH 地址即可。

```
server-https https://cloudflare-dns.com/dns-query
```

小建议由于 TLS 三次握手的特性，查询 DNS 的延迟肯定会提升，建议开启 smartdns 的缓存功能。
玩法三 smartdns 开启广告过滤

下载配置文件到/etc/smartdns 目录：

```bash
wget https://anti-ad.net/anti-ad-for-smartdns.conf -O /etc/smartdns/anti-ad-smartdns.conf
```

修改该/etc/smartdns/smartdns.conf 文件以包含上述配置文件：

```
conf-file /etc/smartdns/anti-ad-smartdns.conf
```

扩展聊一聊（与本文主题无关）

其实直接通过修改系统 DNS 方式解锁流媒体弊端有很多，常见的弊端比如：DNS 服务器宕机导致本地服务无法解析域名、由于厂商分流规则没有细分导致常见 CDN 分配的 IP 在别的地区（常见于 akamai 的 CDN），这时候 DNS 分流就尤为重要。利用 smartdns，可以实现对解锁域名走厂商 DNS，对其他域名走公共 DNS。举个例子，下面那个配置意思是：DAZN 和 Hotstar 走 DNS，其他的全用 8.8.8.8 解析，这样即使 66.66.66.66 宕机，本地只要不访问 DAZN 和 Hotstar 就不受任何影响。

```
server 8.8.8.8
server 66.66.66.66（厂商给的dns ip） -group dns -exclude-default-group

# ---------- > Global Plaform
# > DAZN
nameserver /upos-hz-mirrorakam.akamaized.net/dns
# > Hotstar
nameserver /hotstar.com/dns
```
