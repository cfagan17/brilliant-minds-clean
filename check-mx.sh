#!/bin/bash

echo "Checking MX records for iconoclash.ai..."
echo "========================================="
echo ""

echo "1. MX Records:"
nslookup -type=mx iconoclash.ai
echo ""

echo "2. Using dig for MX:"
dig MX iconoclash.ai +short
echo ""

echo "3. Checking TXT records (for SPF):"
dig TXT iconoclash.ai +short
echo ""

echo "4. Checking nameservers:"
dig NS iconoclash.ai +short
echo ""

echo "5. Testing from multiple DNS servers:"
echo "   Google DNS (8.8.8.8):"
dig @8.8.8.8 MX iconoclash.ai +short
echo ""
echo "   Cloudflare DNS (1.1.1.1):"
dig @1.1.1.1 MX iconoclash.ai +short