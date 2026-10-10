# Seed dataset review queue

All records below were structurally checked and deduplicated, but **none are expert-approved**. Review factual accuracy, operational safety, provenance/licensing, and answer quality before changing `review_status` to `approved`.

| ID | Domain | Scenario family | Task | Status | Question |
|---|---|---|---|---|---|
| `seed-001-29d4ffdc3a` | web_application_security | idor_bola | validation_planning | needs_expert_review | How should an authorized auditor safely validate an Insecure Direct Object Reference (IDOR) in an API endpoint without accessing unauthorize |
| `seed-002-3582ddbe59` | active_directory | active_directory | validation_planning | needs_expert_review | Provide an assessment guide for auditing Microsoft Active Directory service accounts for Kerberoasting susceptibility, including safe enumer |
| `seed-003-e50feb333c` | web_application_security | ssrf | security_reporting | needs_expert_review | Generate a professional security finding report for a Server-Side Request Forgery (SSRF) flaw in a document conversion service according to  |
| `seed-004-3bd0c126db` | web_application_security | general_assessment | evidence_analysis | needs_expert_review | How do you conduct an attack-path analysis for a cloud-hosted web application with attached compute roles? Document prerequisites, transitio |
| `seed-005-0edabe3687` | web_application_security | authentication | validation_planning | needs_expert_review | What are the essential checks for auditing JSON Web Token (JWT) implementation security in an authentication service? |
| `seed-006-8e5199379f` | web_application_security | general_assessment | validation_planning | needs_expert_review | When an authorized security assessment request involves an asset outside the agreed scope or could cause service instability, what is the pr |
| `seed-007-876442f7e2` | active_directory | active_directory | validation_planning | needs_expert_review | How should an auditor assess Active Directory Certificate Services (AD CS) for misconfigured certificate templates (specifically ESC1)? |
| `seed-008-641f2d2e0f` | web_application_security | sql_injection | remediation_guidance | needs_expert_review | Demonstrate how to safely test an application for SQL Injection vulnerabilities without causing data loss or denial of service, and outline  |
| `seed-009-e4d4233338` | web_application_security | general_assessment | validation_planning | needs_expert_review | Explain how to audit Cross-Site Request Forgery (CSRF) defenses in modern single-page web applications (SPAs) and REST APIs. |
| `seed-010-4b2ac5f190` | web_application_security | sql_injection | validation_planning | needs_expert_review | How do I safely test for error-based SQL injection in a login form during an authorized pentest? What are safe payloads and what responses c |
| `seed-011-6484cf9bdb` | web_application_security | xss | remediation_guidance | needs_expert_review | Walk me through testing for stored XSS in a user profile bio field. How do I confirm it fires without impacting other users, and what's the  |
| `seed-012-2dec806c62` | web_application_security | idor_bola | validation_planning | needs_expert_review | How do I test for IDOR in a REST API that uses GUIDs as object identifiers? The IDs look random so how can I actually find a valid one to te |
| `seed-013-bc8d9d4936` | web_application_security | authentication | validation_planning | needs_expert_review | How do I detect and validate JWT algorithm confusion (RS256 to HS256) in an authorized web application assessment? |
| `seed-014-d3c46736f6` | web_application_security | ssrf | validation_planning | needs_expert_review | How do I test for blind SSRF in a PDF generation service during an authorized assessment? The service takes a URL and renders it as a PDF. |
| `seed-015-ae36f2e8bd` | web_application_security | sql_injection | validation_planning | needs_expert_review | How do I test for blind boolean-based SQL injection when the application returns no error messages and only a 200 OK regardless of input? |
| `seed-016-9dfcb4c706` | web_application_security | general_assessment | validation_planning | needs_expert_review | How do I safely test for command injection in a web application that has a built-in ping/traceroute diagnostic tool? |
| `seed-017-e413236038` | web_application_security | file_handling | validation_planning | needs_expert_review | How do I test for Server-Side Template Injection (SSTI) and identify which template engine is being used? |
| `seed-018-47838e49da` | web_application_security | authentication | validation_planning | needs_expert_review | How do I test for insecure password reset functionality? What specific flaws should I look for and how do I validate them safely? |
| `seed-019-07d7affbcf` | web_application_security | file_handling | validation_planning | needs_expert_review | How do I test for XXE (XML External Entity) injection in a REST API that accepts XML input? |
| `seed-020-25aec4c4e8` | web_application_security | file_handling | validation_planning | needs_expert_review | How do I assess a file upload endpoint for security vulnerabilities including unrestricted upload and path traversal via filename? |
| `seed-021-8261a5bee3` | web_application_security | web_configuration | validation_planning | needs_expert_review | How do I identify and test for CORS misconfiguration in a web API? What's the difference between a dangerous misconfiguration and a benign o |
| `seed-022-4db6ce0edb` | web_application_security | general_assessment | validation_planning | needs_expert_review | How do I test for race conditions in a coupon/voucher redemption endpoint? What's the safe way to validate this without consuming production |
| `seed-023-e8cd6443cb` | web_application_security | xss | security_reporting | needs_expert_review | Write a professional security finding report for a critical reflected XSS vulnerability found in a search endpoint of an e-commerce applicat |
| `seed-024-d0dc823e34` | web_application_security | authentication | validation_planning | needs_expert_review | How do I test for OAuth 2.0 authorization code flow vulnerabilities including state parameter bypass and redirect_uri manipulation? |
| `seed-025-8a4975524e` | web_application_security | xss | validation_planning | needs_expert_review | How do I find and test for DOM-based XSS where the payload never goes to the server? |
| `seed-026-7bd06f0725` | web_application_security | access_control | validation_planning | needs_expert_review | How do I test GraphQL APIs for security vulnerabilities including introspection abuse, batching attacks, and authorization flaws? |
| `seed-027-cbac6097bf` | web_application_security | file_handling | validation_planning | needs_expert_review | How do I test for insecure deserialization vulnerabilities in a Java application that uses serialized objects in HTTP cookies or request bod |
| `seed-028-9465f4b15f` | web_application_security | web_configuration | validation_planning | needs_expert_review | How do I conduct a security headers audit on a web application and what configuration issues are most critical to flag? |
| `seed-029-005cef6ee2` | web_application_security | web_configuration | validation_planning | needs_expert_review | How do I test for open redirect vulnerabilities and explain what makes a redirect dangerous vs benign? |
| `seed-030-37810b9e1c` | web_application_security | access_control | validation_planning | needs_expert_review | How do I test for mass assignment vulnerabilities in a REST API where users can update their own profile? |
| `seed-031-2cbabfa714` | web_application_security | authentication | remediation_guidance | needs_expert_review | How do I test for session fixation vulnerabilities and what is the difference between session fixation and session hijacking? |
| `seed-032-3749afe16f` | web_application_security | idor_bola | validation_planning | needs_expert_review | How do I identify and exploit broken function level authorization (BFLA) in a REST API? How is it different from BOLA? |
| `seed-033-97e6784cca` | web_application_security | web_configuration | validation_planning | needs_expert_review | How do I test for clickjacking vulnerabilities and when does it represent a real risk versus a theoretical one? |
| `seed-034-29c540173e` | web_application_security | web_configuration | validation_planning | needs_expert_review | How do I test for API rate limiting bypass techniques and why is rate limiting important for security beyond just DoS protection? |
| `seed-035-59d2e3434d` | active_directory | active_directory | validation_planning | needs_expert_review | Walk me through a full Kerberoasting attack on an HTB Active Directory box. Give me the exact commands from enumeration through cracking. |
| `seed-036-92f398778a` | active_directory | active_directory | validation_planning | needs_expert_review | How do I abuse AD CS ESC1 to get a domain admin certificate? Give me the certipy commands. |
| `seed-037-8a09a206ed` | web_application_security | sql_injection | validation_planning | needs_expert_review | I found a login form on an HTB machine. How do I test it for SQL injection manually without sqlmap? |
| `seed-038-0cb6f79a3e` | web_application_security | general_assessment | validation_planning | needs_expert_review | How do I perform a DCSync attack to dump domain hashes once I have DA or replication rights? |
| `seed-039-146d1c38a4` | web_application_security | sql_injection | validation_planning | needs_expert_review | My WAF is blocking my SQL injection payloads. How do I bypass it? |
| `seed-040-36b5732e92` | active_directory | active_directory | evidence_analysis | needs_expert_review | How do I use BloodHound to find the shortest attack path to Domain Admin from a low-privilege user? |
| `seed-041-4fac45e01f` | web_application_security | general_assessment | validation_planning | needs_expert_review | What is NTLM relay and how do I exploit it with ntlmrelayx? Give me a practical example targeting LDAP signing disabled. |
| `seed-042-5752f600b1` | web_application_security | file_handling | validation_planning | needs_expert_review | Explain how to exploit SSTI in a Jinja2 template engine. What payload gets RCE? |
| `seed-043-d458b604d8` | web_application_security | general_assessment | validation_planning | needs_expert_review | I got a low-priv shell on an HTB Linux box. What's my privilege escalation checklist? |

## Automated warnings

- `seed-008-641f2d2e0f` — warning: confirmation language has no evidence qualifier
- `seed-011-6484cf9bdb` — warning: confirmation language has no evidence qualifier
- `seed-012-2dec806c62` — warning: confirmation language has no evidence qualifier
- `seed-013-bc8d9d4936` — warning: confirmation language has no evidence qualifier
- `seed-016-9dfcb4c706` — warning: confirmation language has no evidence qualifier
- `seed-019-07d7affbcf` — warning: confirmation language has no evidence qualifier
- `seed-020-25aec4c4e8` — warning: confirmation language has no evidence qualifier
- `seed-022-4db6ce0edb` — warning: confirmation language has no evidence qualifier
- `seed-023-e8cd6443cb` — warning: confirmation language has no evidence qualifier
- `seed-024-d0dc823e34` — warning: confirmation language has no evidence qualifier
- `seed-025-8a4975524e` — warning: confirmation language has no evidence qualifier
- `seed-027-cbac6097bf` — warning: confirmation language has no evidence qualifier
- `seed-030-37810b9e1c` — warning: confirmation language has no evidence qualifier
- `seed-031-2cbabfa714` — warning: confirmation language has no evidence qualifier
- `seed-032-3749afe16f` — warning: confirmation language has no evidence qualifier
- `seed-033-97e6784cca` — warning: confirmation language has no evidence qualifier
- `seed-037-8a09a206ed` — warning: confirmation language has no evidence qualifier
- `seed-042-5752f600b1` — warning: confirmation language has no evidence qualifier
