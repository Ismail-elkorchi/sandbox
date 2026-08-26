# Threat model

## Security objective

The sandbox limits what an untrusted target process and all of its descendants can observe, modify, contact, and leave behind. The enforceable contract is the set of guarantees marked `satisfied` in the run's enforcement report. Callers select mandatory guarantees before preparation; execution does not begin if any are unsatisfied.

## Protected assets

Depending on policy and backend, protected host assets include:

- filesystem content, metadata, namespace structure, credentials, user profiles, and runtime sockets outside explicit grants;
- ambient environment variables and inherited file descriptors or handles;
- unrelated host processes, IPC objects, shared memory, and control endpoints;
- host loopback, LAN, private services, cloud metadata endpoints, and external networks;
- approval integrity: executable bytes, exact arguments, working directory, environment identity, policy, and limits;
- runtime availability and ownership, including bounded memory, output, process trees, VMMs, brokers, and cleanup state.

## Attacker capabilities

The target executable, scripts, plugins, dependencies, input workspace, and every descendant are untrusted. They may:

- race path preparation or mutate files in place;
- construct symlinks, magic links, hard links, reparse points, nested mount targets, or hostile metadata;
- inherit or discover descriptors, handles, environment values, processes, IPC, and sockets;
- daemonize, double-fork, detach sessions, exhaust resources, stop reading stdin, or flood output;
- generate malformed protocol, proxy, DNS, image, artifact, or change-set data;
- crash or starve the guest agent, VMM, launcher, broker, or supervisor;
- attempt nested namespaces and platform-specific escape surfaces.

The attacker may control a granted workspace before and during a run. It does not control the trusted host account, installed package directory, release signing key, host kernel/hypervisor, or authorization component.

## Trust boundaries

### TypeScript and native runtime

The TypeScript package validates its public input, verifies package-owned native hashes, launches by retained descriptor where supported, and translates typed messages. Security-sensitive normalization, preparation, digests, setup, enforcement reports, lifecycle, and cleanup are authoritative in Rust.

Node performs no direct native FFI. The Node process and application approval logic are trusted not to replace approved digests or disclose sensitive summaries.

### Linux process backend

The trusted computing base includes the package-owned supervisor and launcher, the managed-network broker when selected, and the host Linux kernel. Namespaces, Landlock, seccomp, mounts, cgroups, rlimits, and descriptor-relative operations compose the process boundary.

This boundary does not defend against a compromised host kernel, kernel vulnerabilities reachable by the target, malicious host administrators, physical attacks, or broad microarchitectural side channels.

### Windows and macOS previews

Windows additionally trusts AppContainer, Job Objects, Windows access checks, and ACL semantics. macOS trusts Seatbelt, process-group signaling, and the guardian lifeline. Both are experimental and report guarantees they cannot establish rather than inheriting Linux claims.

### Firecracker

The hardware-VM trusted computing base additionally includes KVM, the pinned confined Firecracker executable, verified guest kernel and root image, and privileged guest agent. Hardware virtualization reduces shared-kernel exposure but does not remove hypervisor, guest-kernel, VMM, firmware, denial-of-service, or hardware side-channel risk.

The target receives no control nonce, host path, virtual NIC, guest-agent descriptor, or ambient host secret. Inputs are bounded copies. Artifacts and change sets are explicit outputs and never overwrite host paths automatically.

## Fail-closed rules

The runtime does not execute the target when:

- a backend or required mechanism is unavailable;
- native or boot artifact integrity fails;
- policy validation or requirement matching fails;
- prepared authority expires or its digest differs;
- setup cannot establish the exact filesystem, process, resource, or network view;
- an experimental backend lacks both forms of explicit opt-in.

There is no unconfined fallback and no silent backend substitution.

## Approval and race resistance

The Rust runtime returns the summary and digests that an authorization layer must approve. Prepared objects are single-use and time-limited. Environment values marked sensitive are represented by name in summaries while their bytes remain bound to execution identity.

Linux retains grant and working-directory descriptors and snapshots supported executable bytes. VM preparation snapshots verified boot artifacts into private state before launch. Package runtimes and extensions are hash-verified and executed through already-open descriptors or private immutable copies where the platform permits.

These controls bind entry authority. They do not claim that every transitive runtime library, host kernel component, firmware component, or interpreter data file is immutable unless an enforcement fact explicitly says so.

## Network model

`none` provides no external route, host loopback, or virtual NIC as appropriate to the backend. `managed` permits only broker-supported TCP/DNS flows matching normalized deny-by-default rules. The broker rechecks final addresses and private ranges to resist DNS rebinding.

Managed networking does not intercept TLS or inject credentials. It does not support arbitrary UDP, inbound listeners, or raw packets. Unrestricted networking deliberately removes egress confinement and changes related IPC guarantees.

## Availability and cleanup

Resource limits protect the host only to the mechanisms stated in the report. Some resource exhaustion can affect the trusted runtime or host before a backend-specific kernel limit accounts for it; hard guarantees are not reported without an enforcing mechanism.

The runtime owns launchers, descendants, brokers, VMMs, cgroups/jobs, and state. Cleanup is a security result, not a best-effort footnote. Every failed postcondition is returned. Crash recovery uses narrowly validated ownership records and never kills a process based only on an untrusted PID.

## Non-goals

The project does not provide:

- protection from a compromised host, package installation directory, authorization component, kernel, or hypervisor;
- confidentiality against privileged host administrators;
- deterministic execution or side-channel elimination;
- TLS inspection, malware classification, content moderation, or semantic command safety;
- automatic credential brokerage;
- transparent host/guest filesystem synchronization;
- a claim that `noexec` prevents interpreters from reading code as data;
- hostile multi-tenant suitability without an independent published security review.

## Reporting

Generic target stderr is not security evidence. Policy denials are structured runtime or broker events. Suspected boundary failures should be reported privately according to [SECURITY.md](../SECURITY.md), including backend, host version, policy, requested guarantees, and cleanup outcome.
