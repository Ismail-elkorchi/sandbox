# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected sandbox escape, host-data exposure, process-lifecycle failure, integrity bypass, or other security vulnerability.

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include the affected version or commit, host operating system and kernel/build, selected backend, policy, reproduction steps, and the security guarantee that failed.

Avoid including real credentials or unrelated host data. A minimal reproducer and evidence that the target crossed a declared boundary are especially useful.

## Scope and claims

The stable Linux process backend is intended for serious local isolation when its functional probe and exact requirements succeed. Windows, macOS, and Firecracker backends are experimental. No version is claimed suitable for hostile multi-tenant workloads until an external security review is completed with its scope, findings, and tested versions published.

Security reports are evaluated against the guarantee vocabulary and caveats returned in each run's enforcement report. Behavior already reported as an unsatisfied guarantee or explicit caveat may still be a useful hardening report, but it is not a boundary violation.
