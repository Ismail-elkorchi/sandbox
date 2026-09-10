# @ismail-elkorchi/sandbox-hardware-vm

Experimental Firecracker hardware-VM isolation for `@ismail-elkorchi/sandbox`. The extension bundles a pinned VMM, a signed minimal Linux image, an authenticated guest agent, and explicit import, artifact, managed-network, and change-set transports.

```sh
npm install @ismail-elkorchi/sandbox @ismail-elkorchi/sandbox-hardware-vm
```

```ts
import { createSandbox } from "@ismail-elkorchi/sandbox";
import {
  hardwareVmExtension,
  minimalHardwareVmImage,
} from "@ismail-elkorchi/sandbox-hardware-vm";

const sandbox = await createSandbox({
  allowExperimentalImplementations: true,
  extensions: [hardwareVmExtension()],
});

const support = await sandbox.probe({
  isolation: {
    kind: "hardware-vm",
    image: minimalHardwareVmImage(),
    filesystemTransport: "import",
  },
  policy,
  requirements: { allowExperimentalImplementations: true },
  resources,
});
console.dir(support, { depth: null });

const image = minimalHardwareVmImage();
```

The implementation requires Linux x64 and readable/writable `/dev/kvm`. Registering the extension does not silently select it; runs must request `hardware-vm`, opt into experimental implementation use, and provide the selected image.

Explicit resources are copied into guest-owned storage. Guest completion never synchronizes them automatically. Request coordinate-tagged artifacts or a conflict-checked change set, then apply that change set through the exported host helper.

Operational guide: [Firecracker hardware VMs](https://github.com/Ismail-elkorchi/sandbox/blob/main/docs/hardware-vm.md)

Security model: [Threat model](https://github.com/Ismail-elkorchi/sandbox/blob/main/docs/threat-model.md)

Licensed under Apache-2.0.
