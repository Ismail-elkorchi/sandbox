# Getting started

Install Node.js 24 or newer and the unscoped package:

```sh
npm install sandsurf
```

Use a private state directory and an application authorizer for host-authority changes. Ordinary commands and guest filesystem operations do not request new host authority. Linux VM creation requires operator-provisioned bounded ext4 volumes for shared host storage and each machine identity; see the package README's storage requirements. Ordinary directories are not silently treated as physical quotas.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approveInApplication(change),
});
const support = await host.inspect();
console.dir(support); // Unsupported mechanisms and unqualified ones are distinct.

const image = await host.images.importNative({
  manifestPath: "/absolute/complete-machine/manifest.json",
  manifestDigest: "<verified-manifest-sha256>",
});
const machine = await host.machines.create({
  id: "agent-computer",
  image: image.id,
  resources: {
    vcpus: 2,
    memoryMiB: 4096,
    diskBytes: 20 * 1024 ** 3,
    outputBytes: 1024 ** 3,
    managedExecutions: 512,
  },
});

await machine.artifacts.importFromHost({
  source: "/absolute/project",
  destination: "/workspace",
});
const execution = await machine.executions.start({
  argv: ["npm", "test"],
  cwd: "/workspace",
});
const completion = await execution.waitCapture();
for await (const chunk of execution.output.follow()) {
  consume(chunk.stream, chunk.bytes);
}
await host.close();
```

`machine.events.follow({ after, signal })` reads committed history through a
bounded, credit-driven stream, not an SDK polling loop. Save the last consumed
event cursor to resume after disconnection. Each observer has at most one page
in flight; a stalled reader does not hold machine control or the journal writer.
Streams send idle heartbeats and have explicit capacity limits. A reader must
return page credit within 30 seconds or reconnect from its consumed cursor.
They report
transport loss rather than silently reconnecting. Abort the supplied signal to
interrupt an idle read; closing the SDK detaches its observers without stopping
the Linux machine. Stream credit is transport progress, not receipt
acknowledgement, application acceptance, or authorization to delete output.

Native complete-machine bundles can be imported without OCI conversion:

```ts
const nativeImage = await host.images.importNative({
  manifestPath: "/absolute/machine/manifest.json",
  manifestDigest: "<sha256-of-exact-manifest-bytes>",
  operationId: "import-machine",
});
```

Approval binds both the source path and manifest digest. The host verifies every
artifact and durably publishes its own immutable copy. Native distribution
bundles carry each logical system disk as `<manifest-artifact-path>.gz`; boot
artifacts remain their declared files. Imports decode with bounded buffers and
verify the decoded disk digest before publication. npm installation never
expands VM disks or runs image installation hooks. A published operation
can be retrieved or retried after restart even if the source bundle has been
deleted. The same image has one catalog representation regardless of whether
it was imported natively, converted from OCI, or published from a snapshot.
Machine creation and OCI boot recipes require an admitted image. They do not
implicitly install package images or create a second image-publication path.
Provenance carries known sensitivity; a missing sensitivity declaration is not
proof that a complete disk contains no secrets, and imports do not scrub disks.
An image must match the native guest architecture. All adapters use the same
raw system-disk contract. QEMU x64 boot requires a supported 64-bit Linux boot
image or an ELF kernel with a validated physical PVH entry; boot artifacts are
verified before native launch.

OCI conversion accepts a complete Linux OS filesystem with an executable
`/sbin/init` and an explicit boot-image recipe:

```ts
const image = await host.images.importOCI({
  source: { kind: "layout", path: "/absolute/oci-layout" },
  recipe: { bootImage: "<verified-boot-image-sha256>" },
});
```

The recipe selects verified native kernel artifacts. OCI `ENTRYPOINT` and
`CMD` do not become PID 1. The source filesystem must supply its own guest
management integration if guest APIs are needed. Conversion does not run
package scripts on the host. Journaled OCI conversion currently requires a
Linux builder; other hosts report that limitation explicitly.
Archive metadata and decompression are bounded before allocation. The current
filesystem profile preserves numeric ownership, modes, files and links;
unsupported xattrs, ACLs and sparse encodings are rejected, not silently lost.

Guest feature and management-version metadata describe the image build. They
do not require a restricted workload or prove the current guest's integrity.
A kernel without OverlayFS, guest cgroups, seccomp, PTYs or vsock is not rejected
on that basis; APIs requiring unavailable guest facilities fail independently
of native machine power. Management compatibility is checked by the actual
strict guest handshake, not by trusting image provenance.

Disk usage reports host-file lengths and native filesystem allocation for the
machine's retained tree, including directory allocation. It is not Linux free
space, dynamic-disk virtual capacity, or an exclusive physical-space reservation:
shared/reflink extents can be attributed to multiple objects. Windows allocation
is queried from the held file handle, not substituted with file length.
Resource reads use the guardian journal's generation fence, not a native power
query. An unavailable native control channel does not by itself make independent
host storage, retained-output or gateway measurements unavailable.

On Windows, `cpuLedgers` exposes the owned Jobs' CPU and the original WHP
partition's VP/hypervisor counters separately. These are worker-lifetime
observations fenced by `hostCounterEpoch`, not additive machine-lifetime totals.
`cpuMicros` remains absent when a unique whole-computer total is not established;
missing native counters are not reported as zero and do not imply power-off.

`(await machine.resources.usage()).executionsCurrent` counts host-owned managed
admission slots, not Linux PIDs or guest-reported running commands. Admissions
count before the first guest report and remain reserved through management
unavailability, pause and suspend. Native interruption frees their slots, while
retained bytes and unsettled capture headroom remain protected independently.

Captured output payloads are immutable, digest-verified objects owned by the
guardian's retention ledger. Write intent is durable before publication, and
only the ordered chunk commit exposes the bytes as captured. Interrupted writes
recover without replaying Linux commands. Cleanup unlinks a shared object only
when no other captured chunk or pending capture still owns its bytes.

Closing an SDK connection does not stop Linux or its services. Reconnect using the same host directory and durable identities:

```ts
const next = await Sandsurf.open({ directory, authorizer });
const reconnected = await next.machines.connect(machine.id);
const sameExecution = await reconnected.executions.get(execution.id);
```

The default guest account obtains root through ordinary `sudo`. Root can change the OS and disable management. Management failure is reported independently of native power state; `powerOff()` and `destroy()` do not require a responsive management service. Guest process results are observations, not host attestations.

`host.inspect().guestPower` distinguishes unsupported guest shutdown/reboot mechanisms from implemented but unqualified ones. Firecracker x86 lacks ACPI poweroff: Linux can halt while the native VM remains running. Ordinary guest reboot recovery requires a native i8042 reset metric, a clean native exit, and confirmed containment. The guardian commits a new execution generation before booting the same persistent disk under the applied configuration. Arbitrary exits and management loss do not trigger recovery. Kernel panic has no automatic reboot timeout. Other native adapters report reboot unsupported until they provide distinct reset evidence and generation fencing.

`const console = await machine.console.attach()` binds a native serial handle to the current generation independently of guest management. `console.read({ after, maximum })` returns binary bytes, durable cursors, explicit retention loss, and capture status; `console.follow()` uses a bounded credit-driven stream shared with event observation, waking on durable capture rather than polling. Each computer reserves 64 generations with a 512 KiB retained prefix per generation, 1 MiB/s of reads, and 32 KiB/s of input. `console.write(bytes)` accepts at most 4096 bytes and reports the accepted prefix without automatic retry. Reboot fences old input handles; historical output remains readable. `console.detach()` releases the SDK handle while guardian capture continues. `host.inspect().console` reports native attachment support separately from hardware qualification.

Use `machine.fs` for guest paths. Artifact import, capture, comparison and host application operate on explicitly selected content. Host publication requires approval of immutable retained content and its destination. Snapshots, forks, rollback, networking, secrets and publication are independent capabilities, not a prescribed workflow.

Filesystem methods return typed guest observations, not wire envelopes: `stat()`
returns metadata, `list()` returns a bounded page with `Uint8Array` names and
pagination cursor, and `read(path, { offset, maximum })` returns a validated byte
range. `writeFile()` and `writeStream()` return the committed size and digest.
These identify the reported/captured bytes, not an immutable live pathname.
Watchers retain their admitted generation even when the machine handle observes
a newer boot or restore; polling never silently rebinds an old watcher. Polling
uses replayable cursors, so a lost response does not consume its page. Persist
`watcher.identity` and use `machine.fs.attachWatcher(identity)` after reconnect.
The guest journal retains bounded observation history; retention exhaustion or
management-service restart reports `overflow`, requiring a rescan. These are
sampled directory observations, not a guarantee to observe transient changes
between polls. Guest root can modify or delete this journal.

Machine inspection reports host storage separately from native power and guest
management. `storage` describes the ownership phase, declared virtual capacity
and observed payload availability/length. Missing published bytes, invalid
ownership and inaccessible payloads are distinct observations. Inspection never
repairs, recreates or detaches a disk and does not inspect the guest filesystem.
An attached Windows disk may be unreadable to inspection while its native owner
holds exclusive custody; that is not evidence of missing storage or native stop.

Terminals are PTY executions with replayable `terminal` output. Detaching or cancelling a wait does not terminate an execution. Leader exit and output completion are separate; descendants may continue to hold streams open.

Execution requests, states, outcomes and restore lineage are typed observations.
`state.kind` distinguishes `running`, leader-exited `draining`, stream-finalized
`exited`, and `unknown`; an outcome is a closed exit/signal/deadline/failure union.
Receipt reads validate their identity, complete output boundary and canonical
digest before returning, and capture waits require agreement with the completed
guest report. This validation does not attest to guest-root-controlled behavior.

`execution.inspect()` separates the guest `report` from guardian-owned native
`interruption` evidence. A confirmed native stop or superseded execution
generation interrupts pending waits; management-service failure alone does
not. `ExecutionInterruptedError` carries that native observation, not a
fabricated Linux exit status or output-completion receipt. Output following
delivers already retained bytes before reporting interruption; those bytes
remain readable. A reported leader exit remains available independently of
capture completeness. After full-state restore, explicitly reattach through
`executions.get()` to obtain the restored generation; an old handle is not
silently rebound.

Receipt acknowledgement does not release output or express application acceptance. Release requires complete capture elsewhere, continuing retention of the actual bytes, or explicitly authorized loss. A receipt reference alone preserves no bytes. Machine destruction must not release retained output.

`host.operations.get(operationId, { machineId? })` returns an `Operation` handle.
Its cached `observation` and refreshed `inspect()` result distinguish
`host-authority` admissions from `guardian-journal` delivery and retention facts.
Host lifecycle intent is not native power state, configuration admission is not
proof of installation, and receipt acknowledgement is not application acceptance.
Retain the operation ID and lookup scope to reconnect; observations confer no
authority.

`machine.events.read()` and `follow()` return a closed `MachineEventValue` union,
including typed execution reports, native observations and configuration delivery.
Each retained event's digest and cursor coverage are checked before its public
projection is returned. The digest identifies the retained wire event, not the
SDK's projected value. `machine.snapshots.rollback()` returns the same
reconnectable `Operation` model; it does not silently replace live handles.
`snapshot.release({ operationId? })` returns a host-owned retirement operation.
Pending forks, rollback, suspension and image publication prevent retirement;
completed independent copies do not pin their source. Retirement blocks new
uses, but storage remains charged until detached cleanup commits. A full-state
snapshot can remain cleanup-pending while its source VMM retains native input
custody, including after control-channel loss. `host.operations.get(id)` observes
that progress after reconnection. Released snapshot metadata and lineage remain
readable; release never removes retained execution output or receipts.
Authorized resource geometry is available at
`inspection.runtimeConfiguration.resources`, not a competing top-level copy.
The computer state format and native SDK bridge are version 1. Incompatible
stores and bridges are rejected; existing stores are preserved, not migrated.

`execution.output.seal(id, { operationId, boundary? })` creates an independent,
immutable owner for an exact captured prefix, even while the execution is running
or management is unavailable. With no boundary, the first journal admission
selects the current captured prefix; retrying that operation never extends it.
Reconnect with `machine.outputSegment(id)` and use `inspect()` or `read()`.
Sealing shares immutable payloads and canonical framing without double-charging
the original bytes. A partial segment cannot authorize release of a full receipt.
For a complete segment, use `{ kind: "continuing-retention", segment: id }`:
source cleanup retains precisely the frames still owned by segments. Sealing
alone does not rotate a producer's output quota or discard its guest spool.

Native networking, unified storage recovery and immutable restored execution/output lineage are implemented but not qualified by compilation or API tests. Linux hardware qualification is a separate prerequisite-gated run. macOS and Windows complete external resource enforcement remains unsupported; these adapters refuse unenforced machine creation. Consult the reported capabilities and [security scope](../SECURITY.md).
