# Policies and enforcement requirements

Policy describes what the target may access. Requirements describe which guarantees the caller refuses to run without. The runtime normalizes both, reports the mechanisms it can establish, and rejects the run atomically when any required guarantee is unsatisfied.

## Filesystem policy

```ts
filesystem: {
  runtime: { kind: "system" },
  grants: [{
    hostPath: "/absolute/host/workspace",
    targetPath: "/workspace",
    access: "read-write",
    execution: "deny",
    rootResolution: "reject-if-link",
  }],
  masks: [{
    targetPath: "/workspace/.env",
    replacement: "inaccessible",
  }],
  privateHome: { enabled: true, sizeBytes: 64 * 1024 * 1024 },
  temporary: { sizeBytes: 256 * 1024 * 1024, executable: false },
}
```

`runtime: "system"` exposes a backend-defined minimal runtime view, not the host root. On Linux it includes selected executable and library roots plus synthetic identity files. Host homes, `/usr/local`, `/opt`, `/var`, `/run`, host `/tmp`, devices, and host `/proc` are excluded by default. `runtime: "empty"` provides only private runtime scaffolding and explicit grants.

Grant host paths must be absolute. Target paths must be normalized absolute paths in the target path style. Runtime-owned targets, overlapping ambiguous grants, and grants to the target root are rejected. The Linux backend retains descriptors for grant roots and creates mount targets without following target-controlled symlinks.

Read-only grants constrain content, namespace, and metadata mutation. `execution: "deny"` prevents direct kernel execution from that mount; it does not claim that a readable file cannot be interpreted as data by an explicitly available interpreter.

Masks hide a path after grants are installed. Private home and temporary directories are fresh per sandbox and are removed during cleanup.

## Environment

```ts
environment: {
  base: "empty",
  inherit: ["LANG"],
  set: {
    MODE: "batch",
    TOKEN: { value: process.env.TOKEN!, sensitive: true },
  },
  unset: ["LANG"],
}
```

The target never receives the entire Node environment by default. `minimal` creates the documented baseline; `empty` starts with no entries. Only valid portable variable names are accepted. Sensitive values contribute to the execution digest but do not appear in prepared summaries, enforcement reports, or normal error messages.

The trusted native runtime itself is launched with a fixed minimal environment, not the caller's ambient secrets.

## Network

- `{ mode: "none" }` creates an isolated network namespace or platform-equivalent denial and exposes no host loopback.
- `{ mode: "managed", allow: [...] }` keeps the target without a direct external route and brokers supported TCP connections through deny-by-default rules.
- `{ mode: "unrestricted", acknowledgement: "network-is-not-restricted" }` deliberately shares ordinary host networking where supported. Guarantees affected by host network and abstract Unix-socket visibility are reported unsatisfied.

See [managed networking](managed-networking.md) for rule semantics and supported protocols.

## Process policy

The initial contract requires:

```ts
process: {
  hostProcesses: "deny",
  hostIpc: "deny",
}
```

Backend reports distinguish process visibility, process control, shared memory, and IPC endpoints. An IPC endpoint intentionally included inside a grant is not hidden merely because host IPC is otherwise denied.

## Resources

All resolved limits are included in the prepared summary and digests. When omitted, defaults are:

| Limit | Default |
| --- | ---: |
| Wall time | 600,000 ms |
| Memory | half host memory, capped at 4 GiB |
| Processes | 256 |
| Open files per process | 1,024 |
| Single-file size | 1 GiB |
| Combined output | 32 MiB |
| Termination grace | 2,000 ms |

CPU time is optional. The default memory envelope is rejected on hosts where it would be below 512 MiB; provide an explicit value there. Session processes may narrow but never widen their session envelope.

Wall time and output are hard supervisor limits. Linux aggregate memory and process-count guarantees are satisfied only after a functional cgroup v2 delegation probe; otherwise the report states the available fallback and required aggregate guarantees fail preparation.

## Requirements

```ts
requirements: {
  boundary: "os-process",
  required: [
    "runtime.setup-before-exec",
    "filesystem.read-confined",
    "filesystem.content-write-confined",
    "process.complete-tree-termination",
    "network.no-external-connect",
    "resource.wall-time-hard",
    "resource.output-hard",
  ],
}
```

Use `LINUX_PROCESS_BASELINE_REQUIREMENTS` as a conservative Linux starting point. Add network and optional hard-resource guarantees that your application needs. Do not remove requirements based only on the current platform; probe and preparation should decide availability.

Experimental backends require both `createSandbox({ allowExperimentalBackends: true })` and `requirements.allowExperimentalBackend: true`. Hardware VMs also require `boundary: "hardware-virtualized"`.

## Prepared identity

The policy digest binds normalized policy, resolved limits, backend identity, runtime view, and enforcement-relevant configuration. The execution digest additionally binds executable content, exact arguments, working directory, captured environment, stream modes, and artifact/change-set requests.

On Linux, supported executables are snapshotted and executed by descriptor. Shebang scripts bind both script bytes and the verified interpreter entry. Dynamic loaders and shared libraries are runtime-view inputs, so reports distinguish entry-executable binding from complete dependency-graph immutability.
