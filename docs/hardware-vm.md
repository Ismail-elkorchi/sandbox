# Hardware VM extension

`linux-firecracker-v1` is an experimental hardware-virtualized implementation for Linux x64 hosts with writable KVM. Install and register `@ismail-elkorchi/sandbox-hardware-vm`.

```ts
const sandbox = await createSandbox({
  allowExperimentalImplementations: true,
  extensions: [hardwareVmExtension()],
});

const options = {
  isolation: {
    kind: "hardware-vm",
    image: minimalHardwareVmImage(),
    filesystemTransport: "import",
  },
  policy: {
    filesystem: {
      kind: "isolated",
      resources: [{
        id: "workspace",
        source: { space: "host", path: workspace },
        target: { space: "isolated", path: "/workspace" },
        access: {
          content: "read-write",
          directoryEntries: "read-write",
          metadata: "read-write",
          execution: "allow",
        },
        purposes: ["executable", "data"],
      }],
    },
    network: { mode: "none" },
    process: {
      visibility: "session",
      control: "session",
      termination: { scope: "descendant-tree", graceMs: 100 },
    },
    ipc: { visibility: "session" },
  },
  requirements: { allowExperimentalImplementations: true },
  resources: {
    wallTime: { enforcement: "hard", scope: "process", value: 30_000 },
    memory: { enforcement: "hard", scope: "descendant-tree", value: 512 * 1024 * 1024 },
  },
};
```

Import transport copies bounded resource content into guest-owned storage. The guest request has no system-runtime switch and the target root mounts only authorized imports plus requested synthetic directories and implementation-owned kernel filesystems.

Guest completion never writes host resources directly. Artifact requests use isolated coordinate paths. A change-set request names one tagged imported root; applying the returned relative operations is a separate, conflict-checked host action.

Preparation verifies the extension descriptor, runtime, Firecracker binary, kernel, root image, guest agent identity, and workspace template. The target has no virtual NIC. Managed networking uses authenticated guest-initiated Virtio socket tunnels to the policy broker.
