# Implementation support

Selection uses the requested boundary and filesystem topology plus observed mechanism support. The runtime never substitutes another topology after preparation or during recovery.

| Implementation | Boundary | Filesystem | Status | Mechanisms |
| --- | --- | --- | --- | --- |
| `linux-namespace-v1` | OS process | isolated | Stable when eligible | system bubblewrap, retained resource identities, Landlock, seccomp, optional cgroup v2, rlimits |
| `linux-landlock-v1` | OS process | host | Stable when eligible | Landlock, seccomp, subreaper process-group supervision, optional cgroup v2, rlimits |
| `windows-appcontainer-v1` | OS process | host | Stable when eligible; path identity is not claimed | AppContainer, suspended creation, Job Object, handle list, ACL journal |
| `darwin-seatbelt-v1` | OS process | host | Stable when eligible; path identity is not claimed | Seatbelt, guardian, process-group supervision, rlimits |
| `linux-firecracker-v1` | hardware virtualized | isolated imports | Experimental extension | KVM, pinned Firecracker, verified guest, authenticated Virtio socket channel |

`probe()` reports each mechanism as `available`, `unavailable`, `error`, or `not-run`, including the attempted operation and OS error when present. It separately reports implementation availability and eligibility for the supplied request. Preparation then resolves and identity-binds concrete resources.

## Host layouts

Host-layout implementations retain host path names and do not claim isolated name, process, or IPC visibility. Linux uses Landlock for declared filesystem resources, seccomp for denied networking and host-process control, and a subreaper that owns a process group. Windows uses AppContainer access checks and a Job Object. macOS uses a deny-default Seatbelt profile and a guarded process group.

These path-based implementations do not claim executable or resource object identity. A caller that requires either guarantee requests it explicitly and receives an ineligible result. Optional resource limits likewise qualify only where the native mechanism establishes their requested scope.

## Hardware VM

The Firecracker extension supports isolated `import` transport only. It verifies the extension runtime and boot artifacts, copies authorized resources into private guest storage, and exposes only those resources to the target namespace. See [hardware VMs](hardware-vm.md).
