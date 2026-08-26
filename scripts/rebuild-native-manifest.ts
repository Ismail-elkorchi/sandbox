import { createHash } from "node:crypto";
import { lstat, readdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const nativeRoot = resolve("packages/sandbox/native");
const files: Record<string, string> = {};
for (const directory of (await readdir(nativeRoot, { withFileTypes: true }))) {
  if (!directory.isDirectory() || !/^(linux|macos|windows)-(x64|arm64)$/u.test(directory.name)) continue;
  for (const entry of await readdir(resolve(nativeRoot, directory.name), { withFileTypes: true })) {
    if (!entry.isFile() || !/^sandbox-runtime-(linux|macos|windows)-(x64|arm64)(\.exe)?$/u.test(entry.name)) continue;
    const path = resolve(nativeRoot, directory.name, entry.name);
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${path} is not a regular runtime file`);
    files[`${directory.name}/${entry.name}`] = createHash("sha256").update(await readFile(path)).digest("hex");
  }
}
if (Object.keys(files).length === 0) throw new Error("no native runtimes were found");
const manifest = {
  formatVersion: 1,
  buildId: "sandbox-runtime-0.1.0",
  conformanceManifestId: "cross-platform-sandbox-conformance-1",
  files: Object.fromEntries(Object.entries(files).sort(([left], [right]) => left.localeCompare(right))),
};
await writeFile(resolve(nativeRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
