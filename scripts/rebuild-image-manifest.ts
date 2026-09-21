import { createHash } from "node:crypto";
import { lstat, readdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve("packages/sandbox/images");
const required = new Set(
  (process.env.SANDSURF_REQUIRED_IMAGE_ARCHITECTURES ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0),
);
for (const architecture of required) {
  if (architecture !== "x64" && architecture !== "arm64") {
    throw new Error(`unsupported required guest architecture ${architecture}`);
  }
}

const files: Record<string, string> = {};
for (const directory of (await readdir(root, { withFileTypes: true })).sort((left, right) => left.name.localeCompare(right.name))) {
  const match = /^minimal-(x64|arm64)$/u.exec(directory.name);
  if (!directory.isDirectory() || match === null) continue;
  const manifest = resolve(root, directory.name, "manifest.json");
  const metadata = await lstat(manifest);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${manifest} is not a regular image manifest`);
  const relative = `${directory.name}/manifest.json`;
  files[relative] = createHash("sha256").update(await readFile(manifest)).digest("hex");
  required.delete(match[1]!);
}
if (required.size !== 0) throw new Error(`required guest images are absent: ${[...required].join(", ")}`);
if (Object.keys(files).length === 0) throw new Error("no guest images were found");

await writeFile(resolve(root, "manifest.json"), `${JSON.stringify({
  formatVersion: 1,
  buildId: "sandsurf-images-0.1.0",
  files,
}, null, 2)}\n`, { mode: 0o644 });
