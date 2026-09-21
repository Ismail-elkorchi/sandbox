import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const version = "v1.17.0";
const requestedArchitecture = process.env.SANDSURF_ARTIFACT_ARCHITECTURE
  ?? (process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : undefined);
const architecture = requestedArchitecture === "x64" ? "x86_64" : requestedArchitecture === "arm64" ? "aarch64" : undefined;
if (process.platform !== "linux" || architecture === undefined) {
  throw new Error("Firecracker artifacts are available only for Linux x64 and arm64");
}
const archives: Readonly<Record<string, string>> = {
  x86_64: "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
  aarch64: "e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256",
};
const expectedArchive = archives[architecture];
if (expectedArchive === undefined) throw new Error(`no reviewed ${version} archive digest for ${architecture}`);
const temporary = await mkdtemp(resolve(tmpdir(), "sandbox-firecracker-"));
try {
  const archive = resolve(temporary, "firecracker.tgz");
  await run("curl", [
    "--fail",
    "--location",
    "--silent",
    "--show-error",
    `https://github.com/firecracker-microvm/firecracker/releases/download/${version}/firecracker-${version}-${architecture}.tgz`,
    "--output",
    archive,
  ]);
  if (sha256(await readFile(archive)) !== expectedArchive) throw new Error("Firecracker release archive digest mismatch");
  await run("tar", ["-xzf", archive, "-C", temporary]);
  const release = resolve(temporary, `release-${version}-${architecture}`);
  await run("sha256sum", ["--check", "SHA256SUMS", "--ignore-missing"], release);
  const destination = resolve("packages/sandbox/native", `linux-${requestedArchitecture}`);
  await mkdir(destination, { recursive: true });
  for (const [source, name] of [
    [`firecracker-${version}-${architecture}`, `firecracker-${version}-${architecture}`],
    ["LICENSE", "firecracker-LICENSE"],
    ["NOTICE", "firecracker-NOTICE"],
    ["THIRD-PARTY", "firecracker-THIRD-PARTY"],
  ] as const) {
    await copyFile(resolve(release, source), resolve(destination, name));
  }
  await chmod(resolve(destination, `firecracker-${version}-${architecture}`), 0o755);
} finally {
  await rm(temporary, { recursive: true, force: true });
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function run(command: string, args: readonly string[], cwd = process.cwd()): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { cwd, stdio: "inherit" });
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}
