# macOS hardware-VM feasibility evidence

Status: feasibility established; no public backend is registered. Evidence reviewed 2026-08-26.

This report records the platform design and the proof still required before a macOS hardware-VM extension may be exposed. For implemented backends, see the [support matrix](backends.md); for the working Linux VM extension, see [hardware VMs](hardware-vm.md).

## Required platform path

| Requirement | Evidence and design consequence |
| --- | --- |
| Virtualization.framework | [`VZVirtualMachineConfiguration`](https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration) configures Linux VMs and exposes explicit boot loader, storage, network, and socket device lists. The backend can therefore construct a minimal device model instead of accepting an opaque caller configuration. |
| Signing and entitlement | Apple requires the Boolean [`com.apple.security.virtualization`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.virtualization) entitlement, and configuration validation fails without it. The native extension must be a signed, entitled executable; an ordinary unsigned npm native binary is not a releasable path. Probe must check `VZVirtualMachine.supported`, entitlement-backed validation, and artifact signature before advertising availability. |
| Virtio socket transport | A single [`VZVirtioSocketDeviceConfiguration`](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdeviceconfiguration) creates the host/guest socket device. [`VZVirtioSocketDevice`](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdevice) provides port listeners and host-to-guest connections. The existing authenticated guest protocol can be reused over this transport, with a fresh per-VM nonce and the target denied access to the guest control endpoint. |
| Image boot | [`VZLinuxBootLoader`](https://developer.apple.com/documentation/virtualization/vzlinuxbootloader) accepts a Linux kernel, while [`VZVirtioBlockDeviceConfiguration`](https://developer.apple.com/documentation/virtualization/vzvirtioblockdeviceconfiguration) attaches a disk image. The extension must verify the same signed image descriptor, kernel digest, root-image digest, and guest-agent digest before configuration. Architecture must match the host because `VZVirtualMachine` emulates the underlying Mac architecture. |
| No-network behavior | Network devices are an explicit configuration array. `network: none` must configure an empty `networkDevices` array and only the authenticated Virtio socket control device. The release gate still requires a real target-side NIC enumeration and raw-socket egress test on Intel and Apple-silicon hosts. |
| Cleanup | [`VZVirtualMachine.stop()`](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/stop%28completionhandler%3A%29) is the destructive stop operation and has an asynchronous completion result. The owner must await stopped/error state, close socket listeners, detach/delete ephemeral disks, and report every failed postcondition. |

## Proposed backend boundary

The extension owns a signed Swift/Objective-C launcher, validated image files, an ephemeral copy-on-write disk, the `VZVirtualMachine`, and all Virtio socket listeners. Agent-core sees the existing `hardware-vm` contract only. There is no shared-directory device: inputs use bounded protocol import and outputs use explicit artifacts/change sets, preserving the Linux VM filesystem semantics.

## Release blockers

This report does not claim implementation or availability. A future backend remains unavailable until signed Intel and Apple-silicon artifacts pass image boot, no-NIC bypass, authenticated-channel isolation, cancellation/crash cleanup, target-tree, stream-backpressure, artifact, change-set, install-from-tarball, and notarization tests. Managed networking additionally requires the authenticated guest broker transport; NAT or bridged network devices are not an acceptable substitute.
