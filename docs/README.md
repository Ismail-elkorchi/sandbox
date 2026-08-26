# Documentation

Use this directory for operational and architectural details that would interrupt the README's installation path.

## Use the sandbox

- [Getting started](getting-started.md): probing, prepared runs, sessions, cancellation, streams, and results.
- [Policies and requirements](policy.md): filesystem, environment, network, process, resources, and guarantee matching.
- [Backend support](backends.md): platform matrix, stability, availability, and backend-specific limitations.
- [Managed networking](managed-networking.md): supported proxy protocols, rule semantics, DNS, and limitations.
- [Hardware VMs](hardware-vm.md): Firecracker installation, imports, artifacts, change sets, and cleanup.

## Understand and maintain the runtime

- [Threat model](threat-model.md): trust boundary, protected assets, assumptions, non-goals, and security claims.
- [Linux backend internals](linux-backend.md): setup order, enforcement layers, probing, and operational caveats.
- [Runtime protocol](protocol.md): framing, lifecycle, flow control, and compatibility rules.
- [Development](development.md): toolchains, tests, fuzzing, generated artifacts, and release checks.

## Feasibility evidence

These reports document viable platform designs and the evidence still required before registering another hardware-VM backend:

- [macOS Virtualization.framework feasibility](macos-hardware-vm-feasibility.md)
- [Windows HCS feasibility](windows-hardware-vm-feasibility.md)

These reports are not implementation or availability claims.
