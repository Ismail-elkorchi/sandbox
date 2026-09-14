import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { arch, platform, release, tmpdir } from "node:os";
import { join, resolve } from "node:path";

// Qualification deliberately cannot be inferred from these prerequisite checks.
// Boot/containment/owner-death/storage tests need a real, source-built VM runtime.
const source = resolve(import.meta.dirname, "qualification");
const temporary = await mkdtemp(join(tmpdir(), "sandsurf-host-probe-"));
function run(executable: string, args: string[]): string {
  return execFileSync(executable, args, {
    encoding: "utf8", timeout: 60_000, maxBuffer: 256 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}
try {
  let raw: string;
  if (platform() === "linux") {
    const binary = join(temporary, "kvm-probe");
    run("cc", ["-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", join(source, "kvm.c"), "-o", binary]);
    raw = run(binary, []);
  } else if (platform() === "darwin") {
    const binary = join(temporary, "apple-probe");
    run("xcrun", ["swiftc", "-warnings-as-errors", join(source, "apple.swift"), "-o", binary]);
    run("codesign", ["--sign", "-", "--entitlements", join(source, "apple.entitlements"), binary]);
    run("codesign", ["--verify", "--strict", binary]);
    raw = run(binary, []);
  } else if (platform() === "win32") {
    raw = run("pwsh", ["-NoProfile", "-NonInteractive", "-File", join(source, "hyperv.ps1")]);
  } else {
    throw new Error(`No Sandsurf native-host implementation is planned for ${platform()}`);
  }
  const result: unknown = JSON.parse(raw);
  if (typeof result !== "object" || result === null || !("engine" in result) || !("checks" in result) || !Array.isArray(result.checks)) {
    throw new Error("Invalid native prerequisite report");
  }
  const report = JSON.stringify({
    schemaVersion: 1,
    host: { platform: platform(), architecture: arch(), release: release() },
    ...result,
    qualification: {
      kind: "unqualified",
      reasons: ["Prerequisites only: no Sandsurf VM boot, containment, durable storage, or owner-death evidence."],
    },
  }, null, 2) + "\n";
  // An explicit optional output is for CI artifact retention, never host configuration.
  const output = process.argv[2];
  if (output !== undefined) await writeFile(resolve(output), report, { flag: "wx", mode: 0o600 });
  process.stdout.write(report);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
