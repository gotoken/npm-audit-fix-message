# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities through GitHub Security Advisories for
this repository:

https://github.com/gotoken/npm-audit-fix-message/security/advisories/new

If that is not available, open an issue with a minimal description and avoid
including exploit details publicly. A maintainer will follow up with a safer
reporting path.

## Supported Versions

Security fixes are released for the latest published version.

## Security Notes

`npm-audit-fix-message --fix` runs `npm audit` and `npm audit fix` in the
current project. Review npm's changes before committing them, especially in
projects with existing local modifications.
