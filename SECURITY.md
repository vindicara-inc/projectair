# Security Policy

## Reporting a Vulnerability

The Project AIR team takes security seriously. If you discover a security vulnerability in Project AIR, please report it responsibly through one of these channels:

**Preferred:** GitHub Private Vulnerability Reporting
- Use the "Report a vulnerability" button on the Security tab of this repository
- This creates a private advisory only visible to maintainers

**Alternative:** Email
- Send details to security@vindicara.io
- For sensitive disclosures, request our PGP key in your initial email

## What to Include

- Description of the vulnerability
- Affected versions and components
- Steps to reproduce, if applicable
- Potential impact assessment
- Suggested remediation, if known

## Response Commitment

- Acknowledgment within 48 hours
- Initial assessment within 5 business days
- Coordinated disclosure timeline agreed upon with the reporter
- Credit in release notes and CHANGELOG (unless anonymity requested)

## Scope

This policy applies to:
- The `projectair` Python package on PyPI
- The `airsdk` library and `air` CLI
- Project AIR Cloud (cloud.projectair.dev or equivalent)
- All official integrations (OpenAI, Anthropic, LangChain, LlamaIndex, Gemini, ADK)

## Out of Scope

- Issues in third-party dependencies (please report to the dependency maintainer; we'll work with you on coordinated updates)
- Theoretical vulnerabilities without proof of impact
- Social engineering of Vindicara staff

## Supported Versions

Security updates are provided for the latest minor release. Older versions receive critical fixes at the maintainer's discretion.

## Acknowledgments

We maintain a hall of fame for security researchers who have helped improve Project AIR. See ACKNOWLEDGMENTS.md.
