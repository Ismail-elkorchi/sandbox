# Windows hardware-VM feasibility evidence

Status: feasibility established; no public backend is registered. Evidence reviewed 2026-08-26.

This report records the platform design and the proof still required before a Windows hardware-VM extension may be exposed. For implemented backends, see the [support matrix](backends.md); for the working Linux VM extension, see [hardware VMs](hardware-vm.md).

## Required platform path

| Requirement | Evidence and design consequence |
| --- | --- |
| HCS configuration | The official [HCS API reference](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/apioverview) exposes C APIs with JSON configuration for create/start/query/modify/wait/terminate. Microsoft's [VM quick start](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/tutorial) demonstrates schema 2.1, `ShouldTerminateOnLastHandleClosed`, UEFI, memory/CPU topology, and a VHDX-backed SCSI disk. The extension must emit a closed, versioned configuration rather than accept caller JSON. |
| Required host features | Microsoft lists 64-bit CPU, SLAT, VM Monitor Mode extensions, enabled firmware virtualization, hardware DEP, sufficient memory, and supported Pro/Enterprise Windows editions in the [Hyper-V requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements). Probe must additionally open HCS, create a disposable operation, and return unavailable without side effects when the Hyper-V platform is absent. |
| Disk preparation | Hyper-V supports VHD/VHDX and recommends VHDX; [VHDX supports differencing disks](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/features-terminology). A verified immutable base VHDX plus a per-session differencing disk fits ephemeral semantics. HCS also exposes `HcsGrantVmAccess`/`HcsRevokeVmAccess`; every grant and child-disk cleanup must be journaled and recovered after crashes. |
| Hyper-V socket transport | Microsoft's [Hyper-V socket documentation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service) supports host/guest streams without a network stack. Windows uses `AF_HYPERV`; Linux guests use `AF_VSOCK` with `CONFIG_VSOCKET` and `CONFIG_HYPERV_VSOCKETS`. Service registration is host-global and administrative, so installation must register one fixed product service ID and uninstall must remove it; runs use per-VM nonces inside the authenticated protocol. |
| Image boot | HCS schema 2.1 can UEFI-boot a VHDX SCSI attachment as shown by the official quick start. The extension must verify a signed descriptor plus kernel/bootloader, base VHDX, and guest-agent digests before calling HCS; no image is downloaded at runtime. Architecture-specific images are required. |
| No-network behavior | `network: none` omits all synthetic network adapters from the closed HCS configuration. Hyper-V sockets remain the non-IP control transport. Availability still requires guest NIC enumeration and raw IPv4/IPv6/host-loopback egress tests proving that no implicit switch or adapter appears. |
| Cleanup | [`HcsTerminateComputeSystem`](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsterminatecomputesystem) is asynchronous and must be followed by operation-result and compute-system-exit waits. Closing a handle alone is insufficient for a previously created VM, as Microsoft's [compute-system samples](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/computesystemsample) explicitly note. Cleanup therefore terminates, confirms exit, closes operation/system handles, revokes VM file access, and deletes runtime state/differencing disks with journaled recovery. |

## Proposed backend boundary

The extension owns the HCS system and operation handles, the verified base image, per-session VM state and differencing disk, Hyper-V socket listener, and cleanup journal. Inputs and outputs retain the current bounded import/artifact/change-set protocol. No host path is directly mounted into the guest.

## Release blockers

This report does not claim implementation or availability. A future backend remains unavailable until Windows 11 and Windows Server hosts pass feature probing, Linux image boot, no-adapter bypass, authenticated control-plane denial, HCS-owner crash recovery, forced termination, disk/ACL cleanup, artifacts/change sets, stream backpressure, and packed-install tests. Administrator-only service registration must be an explicit install action, never an implicit runtime mutation.
