# macOS hardware-VM feasibility evidence

Status: the source tree contains an entitled Virtualization.framework owner and lifecycle driver, but the complete guest-control/image path has no retained real-hardware qualification. Evidence reviewed 2026-09-21.

This report records the platform constraints and the proof still required before `Sandsurf.inspect()` can report a qualified Apple engine. macOS is a native host target of the one `sandsurf` package, not an optional extension or a host-process fallback.

## Required platform path

| Requirement | Evidence and design consequence |
| --- | --- |
| Virtualization.framework | [`VZVirtualMachineConfiguration`](https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration) configures Linux VMs and exposes explicit boot loader, storage, network, and socket device lists. The implementation can therefore construct a minimal device model instead of accepting an opaque caller configuration. |
| Signing and entitlement | Apple requires the Boolean [`com.apple.security.virtualization`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.virtualization) entitlement, and configuration validation fails without it. The packaged VM owner must be signed and entitled; an ordinary unsigned native binary is not a releasable path. Probe must check `VZVirtualMachine.isSupported`, entitlement-backed validation, and artifact signature before advertising availability. |
| Virtio socket transport | A single [`VZVirtioSocketDeviceConfiguration`](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdeviceconfiguration) creates the host/guest socket device. [`VZVirtioSocketDevice`](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdevice) provides port listeners and host-to-guest connections. The existing authenticated guest protocol can be reused over this transport, with a fresh per-VM nonce and the target denied access to the guest control endpoint. |
| Image boot | [`VZLinuxBootLoader`](https://developer.apple.com/documentation/virtualization/vzlinuxbootloader) accepts a Linux kernel, while [`VZVirtioBlockDeviceConfiguration`](https://developer.apple.com/documentation/virtualization/vzvirtioblockdeviceconfiguration) attaches a disk image. The Apple VM owner must verify the same signed image descriptor, kernel digest, root-image digest, and guest-agent digest before configuration. Architecture must match the host because `VZVirtualMachine` emulates the underlying Mac architecture. |
| No-network behavior | Network devices are an explicit configuration array. `network: none` must configure an empty `networkDevices` array and only the authenticated Virtio socket control device. The release gate still requires a real target-side NIC enumeration and raw-socket egress test on Intel and Apple-silicon hosts. |
| Cleanup | [`VZVirtualMachine.stop()`](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/stop%28completionhandler%3A%29) is the destructive stop operation and has an asynchronous completion result. The owner must await stopped/error state, close socket listeners, detach/delete ephemeral disks, and report every failed postcondition. |

## Proposed implementation boundary

The per-Sandbox guardian owns the signed Swift helper, validated image files, persistent writable disks, the `VZVirtualMachine`, and Virtio socket connections. There is no shared-directory device: host inputs use bounded import and outputs use explicit change sets, preserving the common Linux Sandbox filesystem semantics.

## Release blockers

The engine remains unqualified until signed Intel and Apple-silicon artifacts pass image boot, no-NIC bypass, authenticated-channel isolation, guardian/helper crash containment, persistent disk recovery, concurrent process/PTY replay, filesystem transfer, networking, checkpoint, installed-package, install-from-tarball, and notarization tests. A hosted runner where `VZVirtualMachine.isSupported` is false can validate builds but cannot produce this evidence.
