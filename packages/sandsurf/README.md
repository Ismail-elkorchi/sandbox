# `sandsurf`

Persistent hardware-isolated Linux environments for autonomous agents.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approve(change),
});

const support = await host.inspect();
const image = await host.images.importNative({
  manifestPath: "/absolute/complete-machine/manifest.json",
  manifestDigest: "<verified-manifest-sha256>",
});
const box = await host.machines.create({
  id: "agent-computer",
  image: image.id,
  resources: { vcpus: 2, memoryMiB: 4096, diskBytes: 20 * 1024 ** 3 },
});

const execution = await box.executions.start({
  argv: ["npm", "test"],
  cwd: "/workspace",
});
const completion = await execution.waitCapture();

await host.close(); // The Machine and its services remain owned by the native host.
```

Sandsurf uses one unscoped npm package and a native host service. Linux uses Firecracker/KVM, macOS uses Virtualization.framework, and Windows uses Hyper-V/HCS. `inspect()` reports qualification honestly; no host-process or cloud fallback is selected when hardware virtualization is unavailable.

Installed operation uses independent native services: the host API owns authority; the guardian supervisor launches fixed per-machine owners. Linux API, supervisor, image workers and machine owners have separate externally bounded systemd groups. `sandsurf setup --directory /absolute/state --json` renders the installed service files. Restarting the API does not stop a machine. Account logout and host reboot do not promise RAM/process survival.

Linux machine creation requires operator-provisioned bounded writable ext4 block volumes: one shared host volume at `directory`, plus an independent machine volume at the path printed by `sandsurf storage-path --directory /absolute/state --machine agent-computer`. The machine block capacity must not exceed `physicalStorageBytes`. There is no privileged Sandsurf mount/quota daemon or directory-reservation fallback. Use explicit provisioned identities for creation and forks. The machine volume retains snapshots, journals and output after destruction and cannot be recycled merely because the VM stopped. Shared images belong to the host catalog, not a per-machine image quota. `sandsurf storage-volume` inspects these prerequisites without changing host state. Other platforms report complete external resource enforcement as unsupported until their native mechanisms exist.

The guest administrator can use normal Linux privileges (including sudo), change the system and disable its management service. The host owns authority changes and lifecycle intent; guardians observe native state independently of management availability. SDK handles retain identities and expected revisions, not another authority database. Captured output is not released by acknowledging a receipt or disconnecting.

The breaking redesign is still in progress. Native network enforcement, storage recovery and full-state execution lineage are not yet qualified. Build and API tests are not substitutes for the reported hardware qualification.
