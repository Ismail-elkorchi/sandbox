import { resolve } from "node:path";
import { sha256File } from "../packages/sandsurf/src/file-integrity.ts";
import { dependencySourceFiles, verifyDependencySources } from "./qemu-dependencies.ts";
import { verifyQemuRuntime } from "./qemu-runtime.ts";
import { QEMU_CORRESPONDING_FILES, QEMU_SOURCE } from "./qemu-source.ts";

export type ComponentLicense = { expression: string } | { license: { id: string } };
export interface Component {
  type: string;
  name: string;
  version: string;
  licenses: readonly ComponentLicense[];
  purl?: string;
  hashes?: readonly { alg: string; content: string }[];
  properties?: readonly { name: string; value: string }[];
}

/** Native applications, firmware, and every non-system dynamic library are
 * distribution components. Enumerating Cargo dependencies alone misses them.
 * A manifest/reference never substitutes for verified corresponding bytes. */
export async function nativeComponents(root: string, files: Readonly<Record<string, unknown>>): Promise<Component[]> {
  const components: Component[] = [];
  async function verified(path: string): Promise<string> {
    const actual = await sha256File(resolve(root, path), 512 * 1024 ** 2);
    if (files[path] !== actual) throw new Error(`native supply-chain digest mismatch: ${path}`);
    return actual;
  }
  for (const path of Object.keys(files)) {
    const match = /^linux-(x64|arm64)\/firecracker-v([0-9]+\.[0-9]+\.[0-9]+)-(x86_64|aarch64)$/u.exec(path);
    if (match === null) continue;
    const architecture = match[1]!;
    if ((architecture === "x64") !== (match[3] === "x86_64")) throw new Error("Firecracker architecture mismatch");
    components.push({ type: "application", name: `firecracker (${architecture})`, version: match[2]!,
      purl: `pkg:generic/firecracker@${match[2]}?arch=${architecture}`,
      licenses: [{ license: { id: "Apache-2.0" } }], hashes: [{ alg: "SHA-256", content: await verified(path) }] });
  }
  const platforms = new Set(Object.keys(files).map((path) => path.split('/')[0]!));
  for (const platform of platforms) {
    if (!/^(?:macos-(?:x64|arm64)|windows-x64)$/u.test(platform)) continue;
    const runtime = await verifyQemuRuntime(resolve(root, platform), platform);
    const dependencies = await verifyDependencySources(resolve(root, platform), runtime);
    for (const name of [...Object.keys(runtime), ...dependencySourceFiles(dependencies)]) await verified(`${platform}/${name}`);
    for (const name of QEMU_CORRESPONDING_FILES) await verified(`qemu-source/${name}`);
    const sourceHash = files[`qemu-source/qemu-${QEMU_SOURCE.version}.tar.xz`];
    if (sourceHash !== QEMU_SOURCE.sha256) throw new Error("corresponding QEMU source is not the reviewed release");
    const architecture = platform.endsWith('arm64') ? 'arm64' : 'x64';
    const executable = `sandsurf-qemu-${architecture}${platform.startsWith('windows-') ? '.exe' : ''}`;
    components.push({ type: "application", name: `qemu (${platform})`, version: QEMU_SOURCE.version,
      purl: `pkg:generic/qemu@${QEMU_SOURCE.version}?arch=${architecture}&os=${platform.split('-')[0]}`,
      licenses: [{ expression: "GPL-2.0-or-later" }], hashes: [{ alg: "SHA-256", content: runtime[executable]! }],
      properties: [{ name: "sandsurf:corresponding-source", value: "native/qemu-source" },
        { name: "sandsurf:source-sha256", value: QEMU_SOURCE.sha256 }] });
    for (const [path, digest] of Object.entries(runtime)) {
      if (!path.startsWith('qemu-runtime/firmware/')) continue;
      // The pinned QEMU source release includes these binaries and their
      // corresponding SeaBIOS/option-ROM source. Do not invent a separate
      // firmware upstream version from the outer package's version.
      components.push({ type: "firmware", name: `${path.slice('qemu-runtime/firmware/'.length)} (${platform})`,
        version: `qemu-release-${QEMU_SOURCE.version}`,
        licenses: [{ expression: path.endsWith('bios-256k.bin') ? "GPL-3.0-or-later" : "GPL-2.0-or-later" }],
        hashes: [{ alg: "SHA-256", content: digest }],
        properties: [{ name: "sandsurf:corresponding-source", value: `native/qemu-source/qemu-${QEMU_SOURCE.version}.tar.xz` }] });
    }
    for (const dependency of dependencies.components) {
      components.push({ type: "library", name: `${dependency.name} (${platform})`, version: dependency.version,
        purl: `pkg:generic/${encodeURIComponent(dependency.name)}@${encodeURIComponent(dependency.version)}?arch=${architecture}&os=${platform.split('-')[0]}`,
        licenses: [{ expression: dependency.license }],
        properties: [{ name: "sandsurf:corresponding-source", value: `native/${platform}/qemu-dependencies/${dependency.name}` },
          ...Object.entries(dependency.binaries).flatMap(([path, identity]) => [
            { name: `sandsurf:binary-sha256:${path}`, value: identity.sha256 },
            { name: `sandsurf:installed-binary-sha256:${path}`, value: identity.inputSha256 }])] });
    }
  }
  return components;
}
