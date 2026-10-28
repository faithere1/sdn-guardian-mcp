# Security policy

SDN Guardian pushes access rules to network devices, so safety bugs matter. Examples: a way to
push a rule that skipped or failed simulation, to bypass the management-lockout check, to keep a
rule installed after a failed health check or a missed deadline, or to leak device credentials.

## Reporting a vulnerability

Please **do not open a public issue.** Use GitHub's private reporting instead:
[Report a vulnerability](https://github.com/faithere1/sdn-guardian-mcp/security/advisories/new).

Include the steps to reproduce, the mode (mock or live), and the affected version or commit. You
should get a reply within 7 days.

## Supported versions

Only the latest `main` gets fixes.

## Scope

This is a research and demo project. Mock mode is an emulator, and live mode has been tested
against a simulated IOS-XE device only. Do not run it against production networks without your
own review. See [Safety model & limitations](README.md#safety-model--limitations).
