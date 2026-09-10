# Policy model

`SandboxPolicy` has four independent domains: filesystem, network, process, and IPC. Resource limits are supplied beside the policy because they are hard execution controls with explicit scope.

## Filesystem layouts and coordinates

A host layout restricts access while retaining host path names:

```ts
filesystem: {
  kind: "host",
  resources: [{
    id: "tool",
    path: { space: "host", path: "/opt/tool/bin/tool" },
    access,
    purposes: ["executable"],
  }],
}
```

An isolated layout constructs a filesystem and maps each host source to an isolated target:

```ts
filesystem: {
  kind: "isolated",
  resources: [{
    id: "workspace",
    source: { space: "host", path: "/srv/jobs/42" },
    target: { space: "isolated", path: "/workspace" },
    access: {
      content: "read-write",
      directoryEntries: "read-write",
      metadata: "read-write",
      execution: "deny",
    },
    purposes: ["data"],
  }],
  masks: [{
    path: { space: "isolated", path: "/workspace/secret" },
    replacement: "inaccessible",
  }],
  temporary: {
    path: { space: "isolated", path: "/tmp" },
    sizeBytes: 64 * 1024 * 1024,
  },
}
```

Host and isolated coordinates cannot be mixed. Executable, working-directory, artifact, and change-set root paths use the layout's coordinate space. Artifact results preserve that coordinate tag. Change-set entries remain relative to their tagged root.

There is no implicit runtime resource. A dynamically linked program normally needs separate resources for its executable, interpreter, loader, libraries, and any required data or cache. PATH affects lookup performed by the program; it grants no filesystem access.

Each resource has independent content, directory-entry, metadata, and execution access. An implementation that cannot enforce a requested combination rejects it. Read access to a script still lets an authorized interpreter consume it as data, so direct execution denial is not a non-interpretation claim.

## Process, IPC, and network

```ts
process: {
  visibility: "session",
  control: "session",
  termination: { scope: "descendant-tree", graceMs: 100 },
},
ipc: { visibility: "session" },
network: { mode: "none" },
```

Process visibility and control are separate from termination ownership. IPC visibility covers host endpoints and shared-memory namespaces. Network modes are `none`, policy-brokered `managed`, or explicitly acknowledged `unrestricted`.

## Hard limits and scope

```ts
resources: {
  wallTime: { enforcement: "hard", scope: "process", value: 30_000 },
  memory: { enforcement: "hard", scope: "descendant-tree", value: 512 * 1024 * 1024 },
  processCount: { enforcement: "hard", scope: "descendant-tree", value: 32 },
  output: { enforcement: "hard", scope: "process", value: 8 * 1024 * 1024 },
}
```

Scopes are part of the request. An implementation cannot substitute a per-process limit for a descendant-tree or session limit. Memory, process-count, and CPU limits are absent unless explicitly requested. The remaining defaults are 600,000 ms wall time, 1,024 open files, 1 GiB per file, and 32 MiB output. Resolved limits appear in the prepared summary and digest. Usage in results is measurement, not another limit declaration.

## Requirements and implementation selection

Policy normalization derives its enforcement obligations. `requirements.additional` is only for constraints independent of the policy:

```ts
requirements: {
  additional: ["runtime.executable-identity-bound"],
}
```

Experimental implementations require both `createSandbox({ allowExperimentalImplementations: true })` and `requirements.allowExperimentalImplementations: true`.

Selection is deterministic. The selected implementation identity, build and conformance attribution, normalized policy, concrete resource identities, resolved limits, and executable identity are bound before approval. Unsupported requests stay unsupported.
