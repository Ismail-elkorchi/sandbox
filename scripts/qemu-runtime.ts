import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { QEMU_SOURCE } from "./qemu-source.ts";

export function qemuRequiredInputs(platform: string): string[] {
  const architecture = platform.endsWith("arm64") ? "arm64" : "x64";
  return [`sandsurf-qemu-${architecture}${platform.startsWith("windows-") ? ".exe" : ""}`,
    ...(architecture === "x64" ? ["bios-256k.bin", "linuxboot_dma.bin", "kvmvapic.bin", "pvh.bin"]
      .map((name) => `qemu-runtime/firmware/${name}`) : [])];
}

/** Validate the loaded artifact independently of the outer package index.
 * Source archives and host workers are not QEMU loader inputs. */
export async function verifyQemuRuntime(root: string, platform: string): Promise<Record<string, string>> {
  if (!/^(?:macos-(?:x64|arm64)|windows-x64)$/u.test(platform)) throw new Error("invalid QEMU platform");
  const manifestPath = resolve(root, "qemu-runtime.json");
  await regular(manifestPath, 65536);
  const manifest: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
  if (!record(manifest) || Object.keys(manifest).sort().join(",") !== "architecture,files,formatVersion,qemuVersion"
    || manifest.formatVersion !== 1 || manifest.qemuVersion !== QEMU_SOURCE.version
    || manifest.architecture !== (platform.endsWith("arm64") ? "arm64" : "amd64") || !record(manifest.files)) {
    throw new Error("invalid QEMU runtime manifest");
  }
  const files = manifest.files;
  const required = qemuRequiredInputs(platform), windows = platform.startsWith("windows-");
  if (Object.keys(files).length > 128 || required.some((name) => files[name] === undefined)) {
    throw new Error("incomplete QEMU runtime input closure");
  }
  const library = windows ? /^[A-Za-z0-9_.+-]+\.dll$/iu : /^lib\/[A-Za-z0-9_.+-]+\.dylib$/u;
  let total = 0;
  for (const [name, expected] of Object.entries(files)) {
    if (!required.includes(name) && !library.test(name) || name.length > 132
      || typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) throw new Error("invalid QEMU runtime input role");
    total += await regular(resolve(root, name), 512 * 1024 ** 2);
    if (total > 1024 ** 3 || await runtimeDigest(resolve(root, name)) !== expected) throw new Error("QEMU runtime input digest differs");
  }
  for (const relative of [...(platform.endsWith("x64") ? ["qemu-runtime/firmware"] : []), windows ? "" : "lib"]) {
    const directory = resolve(root, relative), info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("QEMU load directory is an alias");
    const entries = await readdir(directory, { withFileTypes: true });
    if (entries.length > 256) throw new Error("QEMU load directory exceeds its bound");
    const seen = new Set<string>();
    for (const entry of entries) {
      if (windows && relative === "" && !entry.name.toLowerCase().endsWith(".dll")) continue;
      const key = relative === "" ? entry.name : `${relative}/${entry.name}`;
      if (files[key] === undefined || !entry.isFile() || seen.has(entry.name.toLowerCase())) {
        throw new Error("undeclared or aliased QEMU load input");
      }
      seen.add(entry.name.toLowerCase());
    }
  }
  return files as Record<string, string>;
}

export async function runtimeDigest(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const bytes of createReadStream(path, { highWaterMark: 65536 })) hash.update(bytes);
  return hash.digest("hex");
}
async function regular(path: string, maximum: number): Promise<number> {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size === 0 || info.size > maximum) {
    throw new Error("QEMU runtime input is not a bounded independent file");
  }
  return info.size;
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
