# Getting started

Install Node.js 24 or newer and the unscoped package:

```sh
npm install sandsurf
```

Use a private state directory and an application authorizer for host-authority changes. Ordinary commands and guest filesystem operations do not request new host authority.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approveInApplication(change),
});
const support = await host.inspect();
console.dir(support); // Unsupported mechanisms and unqualified ones are distinct.

const machine = await host.machines.create({
  image: "<verified-machine-image-sha256>",
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
artifact and durably publishes its own immutable copy. A published operation
can be retrieved or retried after restart even if the source bundle has been
deleted. The same image has one catalog representation regardless of whether
it was imported natively, converted from OCI, or published from a snapshot.
Provenance carries known sensitivity; a missing sensitivity declaration is not
proof that a complete disk contains no secrets, and imports do not scrub disks.
An image must match the native guest architecture; Windows boot additionally
requires its verified native kernel and VHDX artifacts.

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

`(await machine.resources.usage()).executionsCurrent` counts host-owned managed
admission slots, not Linux PIDs or guest-reported running commands. Admissions
count before the first guest report and remain reserved through management
unavailability, pause and suspend. Native interruption frees their slots, while
retained bytes and unsettled capture headroom remain protected independently.

Closing an SDK connection does not stop Linux or its services. Reconnect using the same host directory and durable identities:

```ts
const next = await Sandsurf.open({ directory, authorizer });
const reconnected = await next.machines.connect(machine.id);
const sameExecution = await reconnected.executions.get(execution.id);
```

The default guest account obtains root through ordinary `sudo`. Root can change the OS and disable management. Management failure is reported independently of native power state; `powerOff()` and `destroy()` do not require a responsive management service. Guest process results are observations, not host attestations.

`host.inspect().guestPower` distinguishes unsupported guest shutdown/reboot mechanisms from implemented but unqualified ones. Firecracker x86 currently lacks ACPI poweroff: Linux can halt while the native VM remains running. Its guest CPU reset terminates the VMM, and ordinary reboot recovery is not implemented. A verified native exit does not change the host's last lifecycle intent or automatically restart the computer. An authorized `start()` preserves disk identity and begins a new execution generation.

Use `machine.fs` for guest paths. Artifact import, capture, comparison and host application operate on explicitly selected content. Host publication requires approval of immutable retained content and its destination. Snapshots, forks, rollback, networking, secrets and publication are independent capabilities, not a prescribed workflow.

Terminals are PTY executions with replayable `terminal` output. Detaching or cancelling a wait does not terminate an execution. Leader exit and output completion are separate; descendants may continue to hold streams open.

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

The breaking redesign remains incomplete. Native network attachments, unified storage recovery, full-state execution lineage and platform hardware qualification still require implementation or qualification; consult the reported capabilities and [security scope](../SECURITY.md).
