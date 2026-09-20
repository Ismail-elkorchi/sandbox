import { createHash } from "node:crypto";
import { lstat, readdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const nativeRoot = resolve("packages/sandbox/native");
const files: Record<string, string> = {};
await collect("");
if (Object.keys(files).length === 0) throw new Error("no native runtimes were found");
const manifest = {
  formatVersion: 1,
  buildId: "sandsurf-native-0.1.0",
  files: Object.fromEntries(Object.entries(files).sort(([left], [right]) => left.localeCompare(right))),
};
await writeFile(resolve(nativeRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });

async function collect(relative: string): Promise<void> {
  for (const entry of await readdir(resolve(nativeRoot, relative), { withFileTypes: true })) {
    const child = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (child === "manifest.json") continue;
    if (entry.isDirectory()) {
      if (relative === "" && !/^(linux|macos|windows)-(x64|arm64)$/u.test(entry.name)) continue;
      await collect(child);
      continue;
    }
    const path = resolve(nativeRoot, child);
    const metadata = await lstat(path);
    if (!entry.isFile() || !metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`${path} is not a regular native artifact`);
    }
    files[child] = createHash("sha256").update(await readFile(path)).digest("hex");
  }
}
