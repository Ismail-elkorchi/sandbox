# Linux namespace backend

`linux-namespace-v1` is the stable process backend. It creates a synthetic filesystem and isolated process context before executing the approved entry object. Availability is based on functional probes, not kernel version or file-presence checks.

## Required host mechanisms

The backend requires:

- Unprivileged user namespaces with a valid UID/GID mapping.
- Mount, PID, IPC, and UTS namespaces.
- A network namespace for `none` and `managed` modes.
- Private mount propagation.
- `no_new_privs` and complete capability dropping.
- A usable Landlock ABI.
- Architecture-specific seccomp filter installation.
- Descriptor-based path and executable operations.
- Procfs and minimal device mounting inside the new root.

There is no Landlock-only or unconfined fallback. If a required namespace or defense layer is unavailable, probe or preparation reports the backend unavailable and no target executes.

## Setup sequence

The multithreaded supervisor never performs unsafe post-fork setup. It starts a dedicated single-threaded launcher and transfers already-open authority descriptors over a bounded Unix socket protocol.

The launcher:

1. Sets a parent-death signal and verifies its parent identity.
2. Creates the required namespaces and UID/GID mappings.
3. Makes mount propagation private.
4. Creates a private tmpfs root and retains its root descriptor.
5. Installs the reviewed system runtime roots or an empty runtime.
6. Creates every mount target through descriptor-relative, no-symlink traversal.
7. Installs retained grant descriptors, masks, private home/temp, private `/proc`, and minimal `/dev`.
8. Opens the descriptor-bound working directory and approved executable snapshot.
9. Applies rlimits, cgroup membership where available, Landlock, seccomp, capability dropping, and `no_new_privs`.
10. Closes all setup descriptors and executes the target.

Runtime-owned targets, root grants, ambiguous overlaps, and the internal `.sandbox-*` namespace are rejected by policy. Internal staging is outside the user-visible root and is never recursively cleaned through a policy-replaceable path.

## Filesystem view

The `system` runtime exposes a reviewed set of executable, library, shared-data, and synthetic configuration paths needed by ordinary command-line programs. It does not expose the host root.

The following are hidden unless a valid explicit grant intentionally supplies data at an allowed target:

- host `/home` and `/root`;
- `/opt` and `/usr/local`;
- `/var` and `/run`;
- host `/tmp`;
- host `/proc`, `/sys`, and `/dev`;
- host account databases and runtime sockets.

The target receives synthetic passwd/group identity, a fresh home and temporary directory, a PID-namespace procfs, and only required synthetic devices.

Grant roots and working directories are opened during preparation with no-magic-link and beneath-root constraints. Target construction uses `openat2`, `mkdirat`, and retained descriptors so a symlink inside a previously mounted workspace cannot redirect trusted setup into a host path.

Read-only mounts are remounted with restrictive flags and reinforced by Landlock. The enforcement report separates content writes, namespace mutations, metadata mutations, reads, and direct execution because no single mount flag proves all of them.

## Executable approval

Supported entry executables are opened during preparation, hashed, copied into a sealed or private immutable snapshot, and executed by descriptor. The execution digest binds the snapshot bytes, exact argument vector, working directory, environment, and stream/output requests.

Shebang scripts are parsed during preparation. The runtime snapshots the script and verifies and binds the interpreter entry, then invokes the verified interpreter explicitly. In-place mutation or path replacement after approval cannot select new entry bytes.

Dynamic loaders and shared libraries remain inputs from the approved runtime view. The report therefore claims entry-executable identity binding, not immutable transitive dependency bytes.

## Process and IPC isolation

The target runs beneath a PID-namespace init that reaps descendants and reports raw wait status. Host processes are absent from the private procfs and cannot be signalled or traced through ordinary PID APIs. IPC and UTS namespaces isolate corresponding kernel objects.

Abstract Unix sockets belong to the network namespace. They are hidden for `none` and `managed`; unrestricted networking truthfully reports that host abstract sockets can remain reachable. IPC endpoints intentionally present inside explicit grants are outside the general hidden-endpoints guarantee.

PID 1 uses incremental nonblocking control decoding and nonblocking target-stdin writes. Lifecycle control, hard timeout, and kill paths cannot be held behind target stdin or output backpressure.

## Networking

`none` and `managed` create a private network namespace with no external route or host loopback. Managed proxy and DNS listeners are created in that namespace and descriptor-passed to the host broker. See [managed networking](managed-networking.md).

Unrestricted mode shares host networking only after the exact acknowledgement string is provided. Network-separation and affected IPC facts are then unsatisfied or caveated.

## Resources

Wall time and output are enforced by the outer supervisor independently of the target. CPU time, open files, and single-file size use rlimits.

Aggregate memory and process-count guarantees use a dedicated workload cgroup, separate from launcher/supervisor overhead. The probe functionally tests child creation, limit writes, process movement, event visibility, `cgroup.kill`, and removal. If delegation is absent, execution can continue only when the caller did not require unavailable aggregate guarantees.

Final status preserves target signals, CPU/file-size limit causes, cgroup OOM evidence, process exhaustion evidence where observable, and runtime-supervision failures.

## Ownership and cleanup

A launch guard owns the launcher, pidfd where available, cgroup, and state until active runtime state is installed. Every setup failure kills the tree, confirms death, reaps it, and records cleanup failures. Active state is installed before any fallible response write.

Parent-death signals bind namespace init to the launcher and the launcher to the Rust supervisor. A separate hard-kill path remains available if internal lifecycle handling stops responding.

Cleanup continues after individual failures and reports:

- whether complete tree death was confirmed;
- whether cgroup and state removal were confirmed;
- each attempted operation that failed.

A target exit code of zero is not evidence that cleanup succeeded.

## Diagnosing unavailability

Start with `sandbox.probe()` and inspect backend capabilities. Common causes include disabled unprivileged user namespaces, unavailable Landlock syscalls, container runtimes that deny nested namespaces, non-private mount setup, unsupported seccomp architecture, and absent cgroup delegation.

Tests skip only after a functional probe says the backend cannot run. For stable release qualification, run the Linux conformance suite on a host where all baseline mechanisms are available.

The Firecracker backend is provided by the separate `@ismail-elkorchi/sandbox-hardware-vm` extension and is never selected implicitly.
