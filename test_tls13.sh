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
    "p9-dy.byteimg.com"
    "mp.weixin.qq.com"
    "coding.net"
    "upyun.com"
    "sns-video-hw.xhscdn.com"
    "sns-img-qc.xhscdn.com"
    "sns-video-qn.xhscdn.com"
    "p6-dy.byteimg.com"
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
for domain in "${domains[@]}"; do
    if test_tls13 "$domain"; then
        supported_domains+=("$domain")
    fi
done

echo ""
echo -e "${GREEN}Domains supporting TLS 1.3:${NC}"
for domain in "${supported_domains[@]}"; do
    echo "  - $domain"
done 
