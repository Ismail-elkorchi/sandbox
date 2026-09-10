# Linux namespace implementation

`linux-namespace-v1` constructs an isolated filesystem and process context with the system bubblewrap executable at `/usr/bin/bwrap`. Bubblewrap must be installed and permitted by the host's security policy. The runtime verifies root ownership and write permissions, retains its executable descriptor, and binds its identity and content digest during preparation. It does not change host security settings.

Linux CI uses Ubuntu 26.04 with its packaged Bubblewrap AppArmor profile. Ubuntu 24.04 does not ship that authorization profile in its standard AppArmor package; on a host enforcing unprivileged-user-namespace restrictions, installing Bubblewrap alone does not make namespace execution eligible. Host policy must authorize the launcher.

Disposable probes exercise the namespace launcher, isolated networking, Landlock, seccomp, and delegated cgroup controllers independently. Eligibility depends on the requested guarantees. Missing memory or process-count delegation does not prevent execution when those limits were not requested.

Preparation opens explicit resources, records their object identities, snapshots executable bytes, and binds policy and execution digests. Symbolic links are resolved through the admitted filesystem: a destination must belong to an admitted resource, respect masks, and permit execution where required. No toolchain, home, or cache directories are implicitly admitted.

Bubblewrap creates the user, mount, PID, IPC, UTS, and requested network namespaces; installs prepared resources, masks, synthetic directories, and executable bytes; and executes the isolated supervisor as PID 1. The supervisor checks mounted object identities before launching the target. Its retained descriptors and memory are inaccessible to targets, and it releases setup authority after forking.

Landlock confines filesystem operations and direct execution. Read-only mounts enforce content, directory-entry, and metadata restrictions. A nested execution denial below an executable resource is rejected because Landlock permissions are additive. Readable code can still be interpreted by an admitted interpreter.

The target receives an explicit environment and standard streams, with no inherited setup descriptors. Capability removal, `no_new_privs`, seccomp, and requested per-process limits precede execution. Managed DNS uses port 53 in the private network namespace; its namespace-local port threshold is configured during setup, and `/proc` is then read-only.

PID-namespace ownership provides descendant cleanup, including daemonized processes and supervisor loss. The isolated supervisor reinstalls its parent-death signal after exec and checks a retained launcher pidfd before starting the target. Explicit memory and process-count limits use a writable cgroup delegation with enabled controllers. Only the gated target enters the group before execution; launcher processes are excluded. A hard memory limit also disables swap for that group, so anonymous pages cannot escape the budget through swap. Session aggregate limits and descendant CPU-time limits remain unsupported.

Child exit, output draining, and completed cleanup are distinct lifecycle states. In-flight stream credits cannot invalidate a completed execution, and delayed consumers cannot return credit to another process. Deadline watchers stop when their process exits.

There is one namespace construction path. A host-filesystem implementation is not qualified. macOS, Windows, and hardware-VM support are described in [implementation support](backends.md).
