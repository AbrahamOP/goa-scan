# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem in Goa Scan itself
(for example: a page able to execute code in the extension context, data leaving the
browser, a secret or cookie value exposed in clear).

Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

Include the affected version, a reproduction (a minimal HTML page is ideal) and the
impact you observed. You will get an acknowledgement within 7 days.

## Scope

In scope: the extension code in this repository.

Out of scope: findings Goa Scan reports about *other* websites. If Goa Scan shows a
problem on a site you do not own, report it to that site's owner — its
`/.well-known/security.txt`, when present, says how.
