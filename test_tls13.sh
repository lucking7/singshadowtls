#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Testing TLS 1.3 Support for Common SNI Domains${NC}"
echo "================================================"

# List of domains to test
domains=(
    "mp.weixin.qq.com"
    "coding.net"
    "upyun.com"
    "sns-video-hw.xhscdn.com"
    "sns-img-qc.xhscdn.com"
    "sns-video-qn.xhscdn.com"
    "p9-dy.byteimg.com"
    "p6-dy.byteimg.com"
    "p11.douyinpic.com"
    "feishu.cn"
    "douyin.com"
    "toutiao.com"
    "v6-dy-y.ixigua.com"
    "hls3-akm.douyucdn.cn"
    "publicassets.cdn-apple.com"
    "weather-data.apple.com"
    "www.microsoft.com"
    "www.apple.com"
    "gateway.icloud.com"
)

# Function to test TLS 1.3 support
test_tls13() {
    local domain=$1
    echo -n "Testing $domain... "
    
    # Test TLS 1.3 connection
    result=$(echo | timeout 5 openssl s_client -tls1_3 -connect "$domain:443" -servername "$domain" 2>&1)
    
    if echo "$result" | grep -q "Protocol  : TLSv1.3"; then
        echo -e "${GREEN}✓ TLS 1.3 Supported${NC}"
        return 0
    else
        echo -e "${RED}✗ TLS 1.3 Not Supported${NC}"
        return 1
    fi
}

# Test each domain
supported_domains=()
unsupported_domains=()
for domain in "${domains[@]}"; do
    if test_tls13 "$domain"; then
        supported_domains+=("$domain")
    else
        unsupported_domains+=("$domain")
    fi
done

echo ""
echo -e "${GREEN}=== Domains supporting TLS 1.3 (${#supported_domains[@]} domains) ===${NC}"
for domain in "${supported_domains[@]}"; do
    echo -e "  ${GREEN}✓${NC} $domain"
done

echo ""
echo -e "${RED}=== Domains NOT supporting TLS 1.3 (${#unsupported_domains[@]} domains) ===${NC}"
for domain in "${unsupported_domains[@]}"; do
    echo -e "  ${RED}✗${NC} $domain"
done

echo ""
echo -e "${YELLOW}Summary:${NC}"
echo -e "  Total tested: ${#domains[@]}"
echo -e "  ${GREEN}TLS 1.3 supported: ${#supported_domains[@]}${NC}"
echo -e "  ${RED}TLS 1.3 not supported: ${#unsupported_domains[@]}${NC}" 
