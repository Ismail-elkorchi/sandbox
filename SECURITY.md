# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected machine escape, host-data exposure, process-lifecycle failure, integrity bypass, or other security vulnerability.

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include the affected version or commit, host operating system and kernel/build, selected implementation, policy, reproduction steps, and the security guarantee that failed.

Avoid including real credentials or unrelated host data. A minimal reproducer and evidence that the target crossed a declared boundary are especially useful.

## Scope and claims

Sandsurf's security boundary is hardware virtualization: Firecracker/KVM on Linux, Apple Virtualization on macOS, and Hyper-V on Windows. Linux namespaces confine the host-side VMM; they are not an alternative guest execution backend. Native availability and real-hardware qualification are different properties. Consult host inspection for the qualification of the actual build and configuration. No version is claimed suitable for hostile multi-tenant workloads without a scoped external security review.

The Linux guest administrator may change or remove guest management software, kill execution keepers, modify its files and copy disclosed credentials. Guest reports, process receipts and guest-held authentication keys do not attest to guest integrity. Native power observations are measured independently through the native owner; query failure is unavailable evidence, not shutdown. Their cause distinguishes lifecycle delivery, configuration installation, and independent native facts. Only operation-attributed evidence can complete host intent or an applied configuration revision. Verified native termination preserves the host's last intent, disks, generation and retained history; a later authorized start establishes a new execution generation.

Guest power support is reported separately from qualification. Firecracker x86 has no ACPI power-management device: Linux `poweroff` may halt the guest while the VM remains running. Guest CPU reset currently terminates Firecracker, rather than providing an ordinary computer reboot. Neither lack of management responses nor halted guest execution proves native termination. These guest power operations remain unsupported where reported by `host.inspect().guestPower`; host-forced power-off remains independent of guest cooperation.

Host-owned authority covers lifecycle intent, limits, externally enforced networking, storage and retained artifacts/output. A receipt acknowledgement is not application acceptance or permission to delete output. Release requires complete durable capture, continuing retention of actual bytes, or explicit loss authorization. Secret revocation prevents future authorized delivery; it does not prove erasure inside a root-controlled guest or its snapshots.

Writable disks have durable physical ownership records distinct from host lifecycle intent. Creation, replacement and retirement share one exclusive mutation lease and journal their phase before namespace changes. A missing published disk or unfinished replacement fails closed; neither permits recreating the computer from its creation image. Retirement preserves a tombstone and does not remove retained output. Replacement and retirement require confirmed native detach/exit: the storage writer lease alone does not prove that a VM attachment has been released.

The breaking redesign remains under development. Native NIC enforcement, recoverable storage ownership and lineage-safe full-state restore are not yet qualified. Report suspected boundary failures even when a capability is marked unqualified, including the host/guest versions and the returned observations.
