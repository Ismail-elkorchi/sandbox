import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, copyFile, mkdtemp, readFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { availableParallelism } from "node:os";
import { spawn } from "node:child_process";

const version = "6.18.41";
const sourceUrl = `https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz`;
const sourceSha256 = "17fc72f0f8d4a8a8633a5d20085f5d9c5a5ec51ee896a0b7ae1ec25da31273ea";
const firecrackerConfigUrl =
  "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260819-0a745def42dd-0/x86_64/vmlinux-6.18.41.config";
const firecrackerConfigSha256 = "c9779a5f7e89c91e371c0a4d15134f46a4cdf2fce6239261edb5c169baec3f2d";
const requestedOutput = process.env.SANDSURF_HYPERV_KERNEL_OUTPUT;
if (requestedOutput !== undefined && !isAbsolute(requestedOutput)) {
  throw new Error("SANDSURF_HYPERV_KERNEL_OUTPUT must be absolute");
}
const output = requestedOutput
  ?? resolve("packages/sandbox/image-build-inputs/x64/hyperv-vmlinuz-6.18.41");

if (process.platform !== "linux" || process.arch !== "x64") {
  throw new Error("the Hyper-V guest kernel builder requires Linux x64");
}

const temporary = await mkdtemp(resolve(tmpdir(), "sandsurf-hyperv-kernel-"));
try {
  const archive = resolve(temporary, `linux-${version}.tar.xz`);
  const config = resolve(temporary, "firecracker.config");
  await run("curl", ["--fail", "--location", "--silent", "--show-error", "--output", archive, sourceUrl]);
  await requireDigest(archive, sourceSha256, "Linux source");
  await run("curl", ["--fail", "--location", "--silent", "--show-error", "--output", config, firecrackerConfigUrl]);
  await requireDigest(config, firecrackerConfigSha256, "Firecracker kernel configuration");
  await run("tar", ["--extract", "--xz", "--file", archive, "--directory", temporary]);

  const source = resolve(temporary, `linux-${version}`);
  const build = resolve(temporary, "build");
  await run("make", ["-C", source, `O=${build}`, "x86_64_defconfig"]);
  await copyFile(config, resolve(build, ".config"));
  await run(resolve(source, "scripts/config"), [
    "--file", resolve(build, ".config"),
    "--enable", "HYPERV",
    "--enable", "BLK_DEV_SD",
  ]);
  const buildEnvironment = {
    KBUILD_BUILD_USER: "sandsurf",
    KBUILD_BUILD_HOST: "builder",
    KBUILD_BUILD_TIMESTAMP: "2023-11-14 22:13:20 UTC",
    KBUILD_BUILD_VERSION: "1",
    SOURCE_DATE_EPOCH: "1700000000",
  };
  await run("make", ["-C", source, `O=${build}`, "olddefconfig"], buildEnvironment);
  const resolvedConfig = (await readFile(resolve(build, ".config"), "utf8")).split("\n");
  for (const required of [
    "CONFIG_BLK_DEV_SD=y",
    "CONFIG_DEVTMPFS=y",
    "CONFIG_EXT4_FS=y",
    "CONFIG_HYPERV=y",
    "CONFIG_HYPERV_STORAGE=y",
    "CONFIG_HYPERV_TIMER=y",
    "CONFIG_HYPERV_VMBUS=y",
    "CONFIG_HYPERV_VSOCKETS=y",
    "CONFIG_OVERLAY_FS=y",
    "CONFIG_SCSI=y",
    "CONFIG_SERIAL_8250=y",
    "CONFIG_VSOCKETS=y",
  ]) {
    if (!resolvedConfig.includes(required)) throw new Error(`Hyper-V kernel lacks ${required}`);
  }
  const jobs = Math.max(1, Math.min(availableParallelism(), 16));
  await run("make", ["-C", source, `O=${build}`, `-j${jobs}`, "bzImage"], buildEnvironment);
  const kernel = resolve(build, "arch/x86/boot/bzImage");
  const bytes = await readFile(kernel);
  if (bytes.byteLength < 0x206 || bytes.subarray(0x202, 0x206).toString("ascii") !== "HdrS") {
    throw new Error("built Hyper-V kernel is not an x86 bzImage");
  }
  const staging = `${output}.new-${process.pid}`;
  await rm(staging, { force: true });
  await copyFile(kernel, staging, constants.COPYFILE_EXCL);
  await chmod(staging, 0o444);
  await rename(staging, output);
  process.stdout.write(`${sha256(bytes)}  ${output}\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}

async function requireDigest(path: string, expected: string, label: string): Promise<void> {
  const observed = sha256(await readFile(path));
  if (observed !== expected) throw new Error(`${label} digest mismatch: ${observed}`);
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function run(
  command: string,
  args: readonly string[],
  environment: Readonly<Record<string, string>> = {},
): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      env: { ...process.env, ...environment },
      stdio: "inherit",
    });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}
