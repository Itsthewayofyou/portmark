# Security Policy

## Supported Versions

Portmark is pre-1.0. Security fixes are supported for the current `main` branch
and the most recent tagged release, when tags exist. Older commits and
development branches are not supported unless a maintainer explicitly says so
in the issue or advisory.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Latest tagged release | Yes |
| Older releases and feature branches | No |

## Reporting A Vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue
for exploitable behavior, secrets exposure, bypasses, or denial-of-service
findings.

Preferred process:

1. Use GitHub Security Advisories for this repository if available.
2. If advisories are not available, contact the repository owner through the
   private contact channel listed on the GitHub repository profile.
3. Include enough detail to reproduce the issue without including live secrets.

Useful report details:

- affected commit, tag, or branch
- affected component, such as A2A, provider, tools, storage, audit, approval, or attestation
- threat model impact and attacker prerequisites
- minimal reproduction steps or test case
- whether public exploitation is known
- any logs or traces with tokens, keys, DSNs, and personal data redacted

## Handling Timeline

The project should acknowledge private reports within 5 business days when a
maintainer is available. Confirmed vulnerabilities should receive a concrete
fix plan, regression test, and release or commit reference before public
disclosure. Timing may vary for dependency issues or deployment-specific
misconfiguration that cannot be fixed entirely in this repository.

## Security Scope

In scope:

- A2A request parsing, authentication, rate limiting, and error handling
- envelope, permit, approval, attestation, and audit-head signature checks
- provider response validation and output projection
- custom tool loading and host-side tool invocation controls
- SQLite and Postgres runtime store semantics
- container, CI, and deployment guidance in this repository

Out of scope:

- attacks that require direct maintainer workstation compromise
- denial of service from a host operator intentionally disabling documented limits
- vulnerabilities in deployment-specific attestation verifier implementations not shipped here
- vulnerabilities in third-party services outside this repository, except where Portmark integrates with them unsafely

## Secrets And Sensitive Data

Never include real private keys, bearer tokens, database passwords, signing
material, customer data, or full runtime checkpoints in public reports. Redact
or replace sensitive values before sharing logs, envelopes, metrics, policies,
or store rows.
