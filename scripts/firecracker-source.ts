import { chmod, copyFile, lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { sha256File } from "../packages/sandsurf/src/file-integrity.ts";

export const FIRECRACKER_VERSION = "v1.17.0";
const archives: Readonly<Record<"x64" | "arm64", string>> = {
  x64: "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
  arm64: "e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256",
};

/** Populate the unpublished Linux platform build. Downloads and native host
 * publication have one owner; there is no partial package-side fetch path. */
export async function fetchFirecracker(destination: string, architecture: "x64" | "arm64"): Promise<void> {
  const machine = architecture === "x64" ? "x86_64" : "aarch64";
  const temporary = await mkdtemp(resolve(tmpdir(), "sandsurf-firecracker-build-"));
  try {
    const archive = resolve(temporary, "firecracker.tgz");
    await run("curl", ["--fail", "--location", "--proto", "=https", "--tlsv1.2",
      "--silent", "--show-error", "--max-time", "300",
      `https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${machine}.tgz`, "--output", archive]);
    const info = await lstat(archive);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 64 * 1024 ** 2
      || await sha256File(archive, 64 * 1024 ** 2) !== archives[architecture]) throw new Error("Firecracker release archive digest mismatch");
    await run("tar", ["-xzf", archive, "-C", temporary]);
    const release = resolve(temporary, `release-${FIRECRACKER_VERSION}-${machine}`);
    await run("sha256sum", ["--check", "SHA256SUMS", "--ignore-missing"], release);
    await mkdir(destination, { recursive: true });
    for (const [source, name] of [
      [`firecracker-${FIRECRACKER_VERSION}-${machine}`, `firecracker-${FIRECRACKER_VERSION}-${machine}`],
      ["LICENSE", "firecracker-LICENSE"], ["NOTICE", "firecracker-NOTICE"], ["THIRD-PARTY", "firecracker-THIRD-PARTY"],
    ] as const) {
      await copyFile(resolve(release, source), resolve(destination, name));
      await chmod(resolve(destination, name), source.startsWith("firecracker-") ? 0o755 : 0o644);
    }
  } finally {
    // Only this invocation's digest-verified tool build input is reclaimed.
    await rm(temporary, { recursive: true, force: true });
  }
}

function run(command: string, args: readonly string[], cwd = process.cwd()): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { cwd, stdio: "inherit" });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => code === 0 ? resolveRun() : rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`)));
  });
}
