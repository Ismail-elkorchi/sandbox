# Backend support

Backend selection is explicit by isolation kind, host platform, and registered extension. The runtime does not substitute a weaker backend when the requested one is unavailable.

## Support matrix

| Backend | Boundary | Hosts | Stability | Main mechanism |
| --- | --- | --- | --- | --- |
| `linux-namespace-v1` | OS process | Linux x64, Linux ARM64 | Stable | namespaces, synthetic root, Landlock, seccomp, cgroup/rlimit supervision |
| `windows-appcontainer-v1` | OS process | Windows x64 | Experimental | AppContainer, suspended creation, Job Object, handle whitelist, ACL journal |
| `darwin-seatbelt-v1` | OS process | macOS x64, macOS ARM64 | Experimental | pre-exec Seatbelt profile, guardian lifeline, process-group supervision |
| `linux-firecracker-v1` | Hardware virtualized | Linux x64 with KVM | Experimental | confined Firecracker, verified Linux guest, authenticated Virtio socket channel |

`sandbox.probe()` returns backend stability, availability, and functional evidence. A backend can be compiled for a platform but unavailable on a particular machine.

## Linux namespaces

The stable backend requires user, mount, PID, IPC, and UTS namespaces; network namespaces for `none` and `managed`; private mount propagation; `no_new_privs`; Landlock; seccomp; and descriptor-bound setup. It has no Landlock-only or unconfined fallback.

Static musl runtimes are bundled for x64 and ARM64. Cgroup-dependent aggregate limits are advertised only after functional creation, limit-write, process-move, kill, event, and cleanup checks. See [Linux backend internals](linux-backend.md).

## Windows AppContainer preview

The Windows backend is opt-in and intentionally narrow:

- `network: "none"` only.
- Canonical same-path grants; target remapping is rejected.
- An AppContainer profile and private profile storage are created per authority.
- Writable grants use an exact ACL journal with startup recovery.
- The target is created suspended, assigned to a kill-on-close Job Object, and only then resumed.
- Explicit inherited handles are restricted to the standard-stream whitelist.

The report does not claim Linux-equivalent path identity, metadata confinement, host IPC isolation, or filesystem behavior for unsupported reparse points, hard links, alternate data streams, case collisions, or device names. GUI applications, installers, services, drivers, and tools requiring ambient handles are outside the compatibility contract.

## macOS Seatbelt preview

The macOS backend applies a generated deny-default Seatbelt profile in a fresh single-threaded launcher before target execution. It supports explicit canonical grants, private home and temporary paths, network denial, a parent-lifeline guardian, and process-group termination.

It reports path-identity limitations and does not claim Linux PID-namespace, complete Mach/bootstrap isolation, metadata-mutation equivalence, or denial of every local service. Operating-system updates can change private Seatbelt behavior, so native CI runs the compatibility suite on supported macOS runners.

## Firecracker preview

The hardware-VM backend is a separately registered extension. It verifies its descriptor, runtime, Firecracker binary, kernel, root image, guest agent identity, and workspace template before boot. Inputs are copied into an ephemeral guest workspace; host paths are never mounted into the guest. See [hardware VMs](hardware-vm.md).

## Hardware-VM feasibility on other hosts

No macOS or Windows hardware-VM backend is registered. The repository contains the required evidence and release blockers for [Virtualization.framework](macos-hardware-vm-feasibility.md) and [HCS](windows-hardware-vm-feasibility.md). These reports are planning evidence, not support claims.
