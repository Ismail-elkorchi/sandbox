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

Guest power support is reported separately from qualification. Firecracker x86 has no ACPI power-management device: Linux `poweroff` may halt the guest while the VM remains running. Its ordinary guest reboot recovery requires native i8042 reset evidence, a clean exit, and confirmed containment; it advances the generation before reattaching the persistent disk under the applied authority. Kernel panic has no automatic reboot timeout. Arbitrary exit, lack of management responses, and halted guest execution never authorize recovery. Adapters without distinct reset evidence report reboot unsupported in `host.inspect().guestPower`; host-forced power-off remains independent of guest cooperation. Native serial input uses an independent descriptor and current generation fence; bounded durable output explicitly reports retention loss and capture failure.

Host-owned authority covers lifecycle intent, limits, externally enforced networking, storage and retained artifacts/output. A receipt acknowledgement is not application acceptance or permission to delete output. Release requires complete durable capture, continuing retention of actual bytes, or explicit loss authorization. Secret revocation prevents future authorized delivery; it does not prove erasure inside a root-controlled guest or its snapshots.

Writable disks have durable physical ownership records distinct from host lifecycle intent. Creation, replacement and retirement share one exclusive mutation lease and journal their phase before namespace changes. A missing published disk or unfinished replacement fails closed; neither permits recreating the computer from its creation image. Retirement preserves a tombstone and does not remove retained output. Linux attachments transfer that same lease through the confined launcher into the actual VMM; Apple attachments transfer it into the VZ owner helper. Custody lasts until native-owner exit, so dropping the guardian or losing its power-query endpoint cannot free the disk early. The lease is not exposed as guest virtual hardware. HCS attachments journal their native identity before creation: crash recovery requires explicit compute-system absence, exclusive disk access and removal of the recorded VM access entry before allowing mutations. Stopped state or an unavailable HCS service is insufficient. Apple and Hyper-V custody still need hardware qualification.

The installed API and guardian-supervision services have separate native service-manager owners. Supervision accepts only bounded fixed guardian launches for an admitted private runtime, not arbitrary host paths or executables; it is not a second lifecycle or grant authority. Linux API, image workers and supervision have externally verified independent process pools. Live guardians/VMMs have machine-specific envelopes; short-lived owners of destroyed-machine journals run inside the bounded supervisor pool. API restart does not signal its guardians. Explicit supervisor shutdown is host-account containment, not ordinary SDK disconnection. Real installed-service VM qualification is distinct from service-definition and process-contract tests.

Physical-storage enforcement uses operator-provisioned bounded ext4 block volumes, not directory reservations. Shared host state/images/build caches occupy the shared host volume; each machine's disks, snapshots, journals and output occupy its independent machine volume. Device capacity must fit the authorized physical cap, including filesystem overhead. Mount roots, aliases and unexpected descendant mounts are rejected. Destruction releases native compute, not retained volume ownership. Operators must not unmount, resize or replace volumes while owners exist; replacing host storage is host authority, not a guest capability. Other platform mechanisms remain explicitly unsupported until implemented and qualified.

Logical identifiers remain case-sensitive and are not host filenames. Host-owned object addresses derive from their exact bytes, so case-insensitive filesystems and Windows device-name rules cannot alias distinct machine, snapshot, secret or operation owners. Addresses are locators, not additional identity or authorization authorities. Incompatible stores are rejected untouched; no alternate address readers or migrations are provided.

The breaking redesign remains under development. Native NIC enforcement, recoverable storage ownership and lineage-safe full-state restore are not yet qualified. Report suspected boundary failures even when a capability is marked unqualified, including the host/guest versions and the returned observations.
