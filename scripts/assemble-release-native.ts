import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const releasePlatforms = ["linux-x64", "linux-arm64", "macos-x64", "macos-arm64", "windows-x64"] as const;

function payload(platform: typeof releasePlatforms[number]): string[] {
  const architecture = platform.endsWith("arm64") ? "arm64" : "x64";
  const host = `sandsurf-host-${platform}${platform.startsWith("windows-") ? ".exe" : ""}`;
  if (platform.startsWith("macos-")) return [host, `sandsurf-vz-helper-${architecture}`];
  if (platform.startsWith("linux-")) return [host,
    `firecracker-v1.17.0-${architecture === "x64" ? "x86_64" : "aarch64"}`,
    "firecracker-LICENSE", "firecracker-NOTICE", "firecracker-THIRD-PARTY"];
  return [host];
}

/** Assemble only this run's verified inputs. Checked-in/debug binaries cannot
 * fill missing platforms. Publish one fresh bundle; preserve replaced outputs. */
export async function assembleNativeRelease(stagingRoot: string, destination: string): Promise<string | undefined> {
  stagingRoot = resolve(stagingRoot); destination = resolve(destination);
  if (basename(destination) !== "native") throw new Error("release destination must be a native artifact directory");
  await directory(stagingRoot);
  await directory(dirname(destination));
  const expectedArtifacts = releasePlatforms.map((platform) => `runtime-${platform}`).sort();
  if (JSON.stringify((await readdir(stagingRoot)).sort()) !== JSON.stringify(expectedArtifacts)) {
    throw new Error("release requires exactly the five advertised native platform artifacts");
  }
  const staged = await mkdtemp(resolve(dirname(destination), ".native-release-"));
  const files: Record<string, string> = {};
  let backup: string | undefined;
  let published = false;
  try {
    for (const platform of releasePlatforms) {
      const artifact = resolve(stagingRoot, `runtime-${platform}`);
      await directory(artifact);
      if (JSON.stringify((await readdir(artifact)).sort()) !== JSON.stringify(["manifest.json", platform].sort())) {
        throw new Error(`${platform} artifact contains unexpected paths`);
      }
      const manifestPath = resolve(artifact, "manifest.json");
      await regular(manifestPath, 1024 * 1024);
      const manifest: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
      if (!record(manifest) || manifest.formatVersion !== 1 || manifest.buildId !== "sandsurf-native-1.0.0" || !record(manifest.files)) {
        throw new Error(`${platform} build manifest is invalid`);
      }
      const source = resolve(artifact, platform);
      await directory(source);
      const names = payload(platform).sort();
      if (JSON.stringify((await readdir(source)).sort()) !== JSON.stringify(names)) {
        throw new Error(`${platform} native payload is incomplete or contains obsolete files`);
      }
      const declared = Object.keys(manifest.files).filter((key) => key.startsWith(`${platform}/`)).sort();
      if (JSON.stringify(declared) !== JSON.stringify(names.map((name) => `${platform}/${name}`))) {
        throw new Error(`${platform} payload differs from its build manifest`);
      }
      await mkdir(resolve(staged, platform));
      for (const name of names) {
        const key = `${platform}/${name}`;
        const expected = manifest.files[key];
        if (typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) throw new Error(`${key} digest is invalid`);
        await regular(resolve(source, name), 512 * 1024 ** 2);
        const target = resolve(staged, key);
        await copyFile(resolve(source, name), target);
        await regular(target, 512 * 1024 ** 2);
        const hash = createHash("sha256");
        for await (const bytes of createReadStream(target, { highWaterMark: 64 * 1024 })) hash.update(bytes);
        if (hash.digest("hex") !== expected) throw new Error(`${key} failed its build digest`);
        // Artifact upload/download does not preserve Unix execute bits. Define
        // release modes from the validated payload role, never inherited modes.
        await chmod(target, name.startsWith("sandsurf-") || name.startsWith("firecracker-v") ? 0o755 : 0o644);
        files[key] = expected;
      }
    }
    await writeFile(resolve(staged, "manifest.json"), `${JSON.stringify({
      formatVersion: 1, buildId: "sandsurf-native-1.0.0",
      files: Object.fromEntries(Object.entries(files).sort(([left], [right]) => left.localeCompare(right))),
    }, null, 2)}\n`, { flag: "wx", mode: 0o644 });
    try {
      await directory(destination);
      const holder = await mkdtemp(resolve(dirname(destination), ".native-checkout-"));
      backup = resolve(holder, "native");
      await rename(destination, backup);
    } catch (error) {
      if (!record(error) || error.code !== "ENOENT") throw error;
    }
    try { await rename(staged, destination); }
    catch (error) { if (backup !== undefined) await rename(backup, destination); throw error; }
    published = true;
    return backup;
  } finally {
    // Only the fresh staging directory created by this invocation is reclaimed.
    if (!published) await rm(staged, { recursive: true, force: true });
  }
}

async function directory(path: string): Promise<void> {
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${path} is not an owned artifact directory`);
}
async function regular(path: string, maximum: number): Promise<void> {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > maximum) throw new Error(`${path} is not a bounded independent artifact`);
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const backup = await assembleNativeRelease(resolve("staged-runtimes"), resolve("packages/sandsurf/native"));
  process.stdout.write(`Assembled all native platforms.${backup === undefined ? "" : ` Previous outputs retained at ${backup}.`}\n`);
}
