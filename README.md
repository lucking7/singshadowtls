# SingShadowTLS

A self-hosted streaming unlock solution using Sing-Box + ShadowTLS + SNI Proxy with automated DNS-based unlocking.

## Architecture

```
Unlock Server                Proxied Server
┌─────────────────┐         ┌─────────────────────┐
│  SNI Proxy      │         │  Sing-Box           │
│  SmartDNS       │◄────────│  ShadowTLS/SS Proxy │
│  (port 80/443)  │  DNS    │  DNS Split Client   │
└─────────────────┘  query  └─────────────────────┘
```

## Scripts

| Script | Deploy On | Description |
|--------|-----------|-------------|
| `install_sniproxy.sh` | Unlock server | Installs SNI Proxy + SmartDNS, auto-extracts streaming unlock rules |
| `sb.sh` | Proxied server | Sing-Box management: ShadowTLS + Shadowsocks proxy, DNS split client |

## Quick Start

```bash
# Unlock server — install SNI Proxy + SmartDNS (server mode)
curl -fsSL https://raw.githubusercontent.com/lucking7/singshadowtls/main/install_sniproxy.sh | \
  sudo bash -s -- -y -a --enable-smartdns --smartdns-mode=server

# Proxied server — install Sing-Box proxy
curl -fsSL https://raw.githubusercontent.com/lucking7/singshadowtls/main/sb.sh | sudo bash
```

## How DNS Unlock Works

1. **Unlock server** runs `install_sniproxy.sh` — SNI Proxy listens on 80/443, SmartDNS resolves streaming domains to the unlock server IP
2. **Proxied server** runs `sb.sh` (option 13) — configures DNS split: streaming domain queries forward to unlock server's SmartDNS
3. Client visits Netflix/Disney → DNS resolves to unlock server IP → SNI Proxy forwards TLS by SNI → streaming unlocked

## Requirements

- Debian/Ubuntu (sb.sh), Debian/Ubuntu/CentOS (install_sniproxy.sh)
- Root privileges

## Documentation

Full setup guide, configuration reference, and troubleshooting are available in the [project wiki](https://github.com/lucking7/singshadowtls/wiki).
