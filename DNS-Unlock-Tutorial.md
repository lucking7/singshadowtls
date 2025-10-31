# DNS Unlock Tutorial: Self-hosted Streaming Service Unlock

## Introduction

There are two approaches to implement self-hosted DNS unlocking: The first is to set up unlocking directly on the server to be unlocked, suitable for scenarios where a single server needs unlocking. The second is to establish a private DNS server, suitable for scenarios where multiple servers need unlocking.

| Comparison Item                     | Solution 1                                                | Solution 2                                                     |
| ----------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------- |
| Set up SNI proxy                    | √                                                         | √                                                              |
| Set up DNS server                   | √                                                         | ×                                                              |
| Local settings on unlocked machines | Only need to modify system DNS                            | Need to set up smartdns on all unlocked machines               |
| Flexibility                         | Quick                                                     | Relatively complex                                             |
| Reliability                         | Local DNS paralysis when self-hosted DNS server goes down | Local DNS works normally when self-hosted DNS server goes down |
| Application scenarios               | Multiple servers                                          | Single server                                                  |

This article chooses to use smartdns instead of Dnsmasq because smartdns is superior in query speed, access speed of queried IPs, and ad filtering compared to Dnsmasq.

## Prerequisites

- 1 streaming unlock server (ports 443 and 80 must not be occupied)

## Setup Tutorial

Since there are two implementation methods, the tutorial has unified steps for SNI proxy setup, while other parts will be explained separately due to differences.

### Install SNI Proxy

```bash
wget --no-check-certificate -O dnsmasq_sniproxy.sh https://raw.githubusercontent.com/myxuchangbin/dnsmasq_sniproxy_install/master/dnsmasq_sniproxy.sh && bash dnsmasq_sniproxy.sh -is
```

### Configure SNI Proxy

Modify the configuration file and format the URLs that need DNS unlocking for input

`/etc/sniproxy.conf`

Format example:

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

### Restart SNI Proxy

```bash
systemctl restart sniproxy
```

### Set Unlock Whitelist on Unlock Server

If ufw is not installed, execute first:

```bash
sudo apt install ufw
ufw enable
```

Be sure to allow the current SSH port on first installation

```bash
sudo ufw allow 22/tcp
```

Modify the IP in the example below (write the IP of the machine to be unlocked), then execute.

```bash
sudo ufw allow from 2.2.2.2 to any port 443 proto tcp
sudo ufw allow from 2.2.2.2 to any port 443 proto udp
sudo ufw allow from 2.2.2.2 to any port 80 proto tcp
sudo ufw allow from 2.2.2.2 to any port 80 proto udp
```

## Solution 1: Install smartdns and Set Up DNS Server

You can use another server here, or use the same server where the SNI proxy was set up.

```bash
wget https://github.com/pymumu/smartdns/releases/download/Release46/smartdns.1.2024.06.12-2222.x86-linux-all.tar.gz
tar zxf smartdns.1.2024.06.12-2222.x86-linux-all.tar.gz
cd smartdns
chmod +x ./install
./install -i
```

### Configure smartdns

```bash
vi /etc/smartdns/smartdns.conf
```

Edit the configuration, add the URLs that need unlocking yourself. For common streaming domains, you can refer to the ones prepared by 1stream.

Format example:

```
bind[::]:53@eth0 -no-dualstack-selection -no-speed-check # Don't touch this
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
server 210.0.255.250 # Default upstream DNS
server 210.0.255.251 # Default upstream DNS

# ---------- > Global Platform
# > GPT
address /openai.com/UnlockServerIP
address /chatgpt.com/UnlockServerIP
address /oaistatic.com/UnlockServerIP
address /oaiusercontent.com/UnlockServerIP
```

Save and start

```bash
systemctl enable smartdns
systemctl start smartdns
```

### Enable DNS Whitelist on DNS Server

Strongly recommend enabling DNS whitelist. Without it, others can freeload, and it might be used by attackers for DNS amplification attacks.

Enable whitelist

Modify the IP in the example below.

```bash
ufw allow from 2.2.2.2 to any port 53 proto udp
```

### Modify DNS on Servers to be Unlocked

Change DNS to the IP of the unlock server or DNS server.

```bash
vim /etc/resolv.conf
```

## Solution 2

Set up smartdns locally on the server to be unlocked

Installation steps are the same as Solution 1, not repeated here.

The configuration file has changes. The specific change is in the first line of DNS settings, which restricts access to local only.

Format example:

```
bind :53@lo -no-dualstack-selection -no-speed-check # Don't touch this
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
server 210.0.255.250 # Default upstream DNS
server 210.0.255.251 # Default upstream DNS


# ---------- > Global Platform
# > GPT
address /openai.com/UnlockServerIP
address /chatgpt.com/UnlockServerIP
address /oaistatic.com/UnlockServerIP
address /oaiusercontent.com/UnlockServerIP
```

### Modify DNS on Server to be Unlocked

Change DNS to 127.0.0.1

```bash
vim /etc/resolv.conf
```

## Advanced Techniques

### Technique 1: Nested Unlocking

Actually, servers that provide DNS unlocking from certain merchants can also use this tutorial to provide unlocking to other servers, which is nested unlocking (this behavior may violate TOS).

Using Solution 1 with self-hosted DNS, you just need to modify the upstream DNS settings and domain-corresponding DNS settings to implement it.

```
server 210.0.255.250 # Default upstream DNS
server 210.0.255.251 # Default upstream DNS
server Write merchant provided DNS IP here -group dnsproxy -exclude-default-group

# > Netflix
nameserver /netflix.com/dnsproxy
nameserver /netflix.net/dnsproxy
nameserver /nflximg.com/dnsproxy
nameserver /nflximg.net/dnsproxy
nameserver /nflxvideo.net/dnsproxy
nameserver /nflxext.com/dnsproxy
nameserver /nflxso.net/dnsproxy
```

### Technique 2: Self-hosted DOH Server

Some providers forcibly hijack UDP traffic on port 53, making it impossible to escape the provider's unlocking service no matter how you change DNS. This is when DOH comes in handy.

DOH simply means DNS over HTTPS. By using DOH with TCP traffic and TLS, you can perfectly bypass DNS hijacking.

smartdns can set up a DOH server, but I didn't succeed in setting it up, so sad. So I only introduce setting up DOH with AdGuardHome.

There are already many tutorials online for setting up DOH with AdGuardHome, so I'll skip it here. During setup, the only thing to note is that upstream DNS needs to be written as 127.0.0.1.

Servers with DNS hijacking only need to set the default DNS in smartdns to the DOH address they just built.

```
server-https https://cloudflare-dns.com/dns-query
```

Small suggestion: Due to the characteristics of TLS three-way handshake, DNS query latency will definitely increase. It is recommended to enable smartdns caching.

### Technique 3: Enable Ad Filtering in smartdns

Download the configuration file to the /etc/smartdns directory:

```bash
wget https://anti-ad.net/anti-ad-for-smartdns.conf -O /etc/smartdns/anti-ad-smartdns.conf
```

Modify the /etc/smartdns/smartdns.conf file to include the above configuration file:

```
conf-file /etc/smartdns/anti-ad-smartdns.conf
```

## Additional Discussion (Unrelated to Main Topic)

Actually, unlocking streaming services by directly modifying system DNS has many drawbacks. Common drawbacks include: DNS server downtime causing local services to fail domain resolution, provider sharding rules not being detailed enough causing common CDN-allocated IPs to be in other regions (common with Akamai CDN). This is when DNS sharding becomes particularly important. Using smartdns, you can implement unlocked domains using provider DNS, while other domains use public DNS. For example, the configuration below means: DAZN and Hotstar use DNS, everything else uses 8.8.8.8 resolution. This way, even if 66.66.66.66 goes down, local services are unaffected as long as DAZN and Hotstar are not accessed.

```
server 8.8.8.8
server 66.66.66.66 (provider given dns ip) -group dns -exclude-default-group

# ---------- > Global Platform
# > DAZN
nameserver /upos-hz-mirrorakam.akamaized.net/dns
# > Hotstar
nameserver /hotstar.com/dns
```

