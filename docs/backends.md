# Implementation support

Selection uses the requested boundary and filesystem topology plus observed mechanism support. The runtime never substitutes another topology after preparation or during recovery.

| Implementation | Boundary | Filesystem | Status | Mechanisms |
| --- | --- | --- | --- | --- |
| `linux-namespace-v1` | OS process | isolated | Stable when eligible | system bubblewrap, retained resource identities, Landlock, seccomp, optional cgroup v2, rlimits |
| `windows-appcontainer-v1` | OS process | host | Experimental; object identity guarantees are not implemented | AppContainer, suspended creation, Job Object, handle list, ACL journal |
| `darwin-seatbelt-v1` | OS process | host | Experimental; object identity guarantees are not implemented | Seatbelt, guardian, process-group supervision, rlimits |
| `linux-firecracker-v1` | hardware virtualized | isolated imports | Experimental extension | KVM, pinned Firecracker, verified guest, authenticated Virtio socket channel |

`probe()` reports each mechanism as `available`, `unavailable`, `error`, or `not-run`, including the attempted operation and OS error when present. It separately reports implementation availability and eligibility for the supplied request. Preparation then resolves and identity-binds concrete resources.

## Linux host layout

No unprivileged Linux host-layout implementation is adopted. Landlock can confine selected filesystem operations, but it cannot by itself provide the requested process visibility, IPC namespace topology, isolated name visibility, and unescapable descendant-tree cleanup. The runtime therefore reports host-layout requests as ineligible instead of weakening those properties.

## Portable previews

The macOS and Windows implementations report their actual path, process, IPC, and resource-control limitations. Their path-based launch mechanisms do not currently establish the executable and resource object-identity obligations required by the policy, so exact requests remain ineligible. Their native probes and conformance attribution stay visible for continued implementation work.

## Hardware VM

The Firecracker extension supports isolated `import` transport only. It verifies the extension runtime and boot artifacts, copies authorized resources into private guest storage, and exposes only those resources to the target namespace. See [hardware VMs](hardware-vm.md).
