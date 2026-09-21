import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { spawn } from "node:child_process";

const kernelName = "vmlinux-6.18.41";
const kernelBaseUrl = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260819-0a745def42dd-0/x86_64";
const kernelUrl = `${kernelBaseUrl}/${kernelName}`;
const kernelSha256 = "645688b5933cb257f7d4fa71eb246669233e8c2db8378217c99cf891541fe3d5";
const kernelConfigUrl = `${kernelUrl}.config`;
const kernelConfigSha256 = "c9779a5f7e89c91e371c0a4d15134f46a4cdf2fce6239261edb5c169baec3f2d";
const localBuild = process.env.SANDSURF_LOCAL_IMAGE === "1";
const signingKeyPath = process.env.SANDBOX_IMAGE_SIGNING_KEY_FILE;
let releaseSeed: Buffer | undefined;
if (!localBuild) {
  if (signingKeyPath === undefined || !isAbsolute(signingKeyPath)) {
    throw new Error("SANDBOX_IMAGE_SIGNING_KEY_FILE must name an absolute file containing a 32-byte Ed25519 seed");
  }
  const signingKeyMetadata = await stat(signingKeyPath);
  if (!signingKeyMetadata.isFile() || (signingKeyMetadata.mode & 0o077) !== 0) {
    throw new Error("the image signing seed must be a private regular file");
  }
  releaseSeed = await readFile(signingKeyPath);
  if (releaseSeed.byteLength !== 32) throw new Error("the image signing seed must contain exactly 32 bytes");
}
const releasePublicKey = "495b4a26a65df66f7090065ed23a30a29ad3b53e0ed90d6506a2d6c8c0aba684";
const busyboxPath = process.env.SANDBOX_BUSYBOX_PATH ?? "/usr/bin/busybox";
const caBundlePath = process.env.SANDBOX_CA_BUNDLE_FILE ?? "/etc/ssl/certs/ca-certificates.crt";
if (!isAbsolute(busyboxPath) || !isAbsolute(caBundlePath)) {
  throw new Error("guest runtime inputs must use absolute paths");
}
const guestProtocolSource = await readFile(resolve("crates/sandbox-guest/src/lib.rs"), "utf8");
const guestProtocolMajor = Number(/GUEST_PROTOCOL_MAJOR: u16 = ([0-9]+);/u.exec(guestProtocolSource)?.[1]);
const guestProtocolMinor = Number(/GUEST_PROTOCOL_MINOR: u16 = ([0-9]+);/u.exec(guestProtocolSource)?.[1]);
if (!Number.isSafeInteger(guestProtocolMajor) || !Number.isSafeInteger(guestProtocolMinor)) throw new Error("guest protocol version is not declared");

if (process.platform !== "linux" || process.arch !== "x64") {
  throw new Error("the initial guest image builder requires Linux x64");
}

const temporary = await mkdtemp(resolve(tmpdir(), "sandbox-guest-image-"));
try {
  await run("cargo", ["build", "--release", "-p", "sandbox-guest", "--target", "x86_64-unknown-linux-musl"], process.cwd(), {
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER: "rust-lld",
  });
  const guestAgent = resolve("target/x86_64-unknown-linux-musl/release/sandbox-guest");
  const guestBytes = await readFile(guestAgent);
  if (!isElf(guestBytes)) throw new Error("guest agent is not an ELF executable");

  const root = resolve(temporary, "bootstrap");
  for (const path of [
    "dev", "proc", "run", "sandsurf/control", "sandsurf/lower", "sandsurf/state",
    "sandsurf/workload", "sbin", "sys/fs/cgroup", "tmp",
  ]) {
    await mkdir(resolve(root, path), { recursive: true });
  }
  const workloadRoot = resolve(temporary, "workload");
  for (const path of ["bin", "etc/ssl/certs", "home/agent", "run", "tmp", "workspace"]) {
    await mkdir(resolve(workloadRoot, path), { recursive: true });
  }
  const busyboxBytes = await boundedRegularFile(busyboxPath, 64 * 1024 * 1024, "BusyBox");
  if (!isElf(busyboxBytes)) throw new Error("BusyBox is not an ELF executable");
  await assertStaticElf(busyboxPath, "BusyBox");
  await copyFile(busyboxPath, resolve(workloadRoot, "bin/busybox"));
  await chmod(resolve(workloadRoot, "bin/busybox"), 0o755);
  for (const applet of [
    "cat", "chmod", "cp", "env", "false", "ls", "mkdir", "mv", "printf", "rm", "sh",
    "sleep", "test", "touch", "true", "uname",
  ]) {
    await symlink("busybox", resolve(workloadRoot, "bin", applet));
  }
  const caBundle = await boundedRegularFile(caBundlePath, 4 * 1024 * 1024, "CA bundle");
  if (caBundle.includes(0) || !caBundle.includes(Buffer.from("-----BEGIN CERTIFICATE-----", "ascii"))) {
    throw new Error("CA bundle is not a PEM certificate bundle");
  }
  await copyFile(caBundlePath, resolve(workloadRoot, "etc/ssl/certs/ca-certificates.crt"));
  await chmod(resolve(workloadRoot, "etc/ssl/certs/ca-certificates.crt"), 0o644);
  await symlink("certs/ca-certificates.crt", resolve(workloadRoot, "etc/ssl/cert.pem"));
  await copyFile(guestAgent, resolve(root, "sbin/sandbox-guest"));
  await chmod(resolve(root, "sbin/sandbox-guest"), 0o755);
  await writeFile(resolve(workloadRoot, "etc/passwd"), "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000:agent:/home/agent:/bin/sh\n", { mode: 0o644 });
  await writeFile(resolve(workloadRoot, "etc/group"), "root:x:0:\nagent:x:1000:\n", { mode: 0o644 });
  await normalizeTimestamps(root);
  await normalizeTimestamps(workloadRoot);

  const rootfs = resolve(temporary, "minimal-bootstrap.ext4");
  await createSparse(rootfs, 32 * 1024 * 1024);
  await run(
    "mkfs.ext4",
    ["-F", "-q", "-O", "^has_journal", "-U", "11111111-1111-4111-8111-111111111111", "-E", "lazy_itable_init=0,lazy_journal_init=0", "-d", root, rootfs],
    process.cwd(),
    { E2FSPROGS_FAKE_TIME: "1700000000" },
  );
  await normalizeExt4(rootfs, 8192, "33333333-3333-4333-8333-333333333333", temporary, true);
  const workload = resolve(temporary, "minimal-workload.ext4");
  // Keep the distributable raw image below common source-hosting blob limits.
  // The immutable minimal workload occupies only a few MiB; mutable package
  // installations and caches live on the separately sized state disk.
  await createSparse(workload, 96 * 1024 * 1024);
  await run(
    "mkfs.ext4",
    ["-F", "-q", "-O", "^has_journal", "-U", "55555555-5555-4555-8555-555555555555", "-E", "lazy_itable_init=0,lazy_journal_init=0", "-d", workloadRoot, workload],
    process.cwd(),
    { E2FSPROGS_FAKE_TIME: "1700000000" },
  );
  await normalizeExt4(workload, 24576, "66666666-6666-4666-8666-666666666666", temporary, true);
  const workspace = resolve(temporary, "empty-workspace.ext4");
  const empty = resolve(temporary, "empty");
  await mkdir(empty);
  await normalizeTimestamps(empty);
  await createSparse(workspace, 64 * 1024 * 1024);
  await run(
    "mkfs.ext4",
    ["-F", "-q", "-U", "22222222-2222-4222-8222-222222222222", "-E", "lazy_itable_init=0,lazy_journal_init=0", "-d", empty, workspace],
    process.cwd(),
    { E2FSPROGS_FAKE_TIME: "1700000000" },
  );
  await normalizeExt4(workspace, 16384, "44444444-4444-4444-8444-444444444444", temporary, false);

  const kernel = resolve(temporary, kernelName);
  await run("curl", ["--fail", "--location", "--silent", "--show-error", "--output", kernel, kernelUrl]);
  if (sha256(await readFile(kernel)) !== kernelSha256) throw new Error("guest kernel digest mismatch");
  const kernelConfig = resolve(temporary, `${kernelName}.config`);
  await run("curl", ["--fail", "--location", "--silent", "--show-error", "--output", kernelConfig, kernelConfigUrl]);
  const kernelConfigBytes = await readFile(kernelConfig);
  if (sha256(kernelConfigBytes) !== kernelConfigSha256) throw new Error("guest kernel configuration digest mismatch");
  const kernelConfiguration = kernelConfigBytes.toString("utf8");
  for (const required of [
    "CONFIG_CGROUPS=y", "CONFIG_DEVTMPFS=y", "CONFIG_IPV6=y", "CONFIG_OVERLAY_FS=y",
    "CONFIG_SECCOMP=y", "CONFIG_TUN=y", "CONFIG_VIRTIO_VSOCKETS=y", "CONFIG_VSOCKETS=y",
  ]) {
    if (!kernelConfiguration.split("\n").includes(required)) throw new Error(`guest kernel lacks ${required}`);
  }

  const explicitOutput = process.env.SANDSURF_IMAGE_OUTPUT_DIRECTORY;
  if (explicitOutput !== undefined && !isAbsolute(explicitOutput)) throw new Error("SANDSURF_IMAGE_OUTPUT_DIRECTORY must be absolute");
  const destination = explicitOutput ?? resolve("packages/sandbox/images/minimal-x64");
  const native = explicitOutput ?? resolve("packages/sandbox/native/linux-x64");
  await mkdir(destination, { recursive: true });
  await mkdir(native, { recursive: true });
  for (const retired of ["minimal-rootfs.ext4", "vmlinux-6.1.177"]) {
    await rm(resolve(destination, retired), { force: true });
  }
  await replaceArtifact(kernel, resolve(destination, kernelName));
  await replaceArtifact(rootfs, resolve(destination, "minimal-bootstrap.ext4"));
  await replaceArtifact(workload, resolve(destination, "minimal-workload.ext4"));
  await replaceArtifact(workspace, resolve(destination, "empty-workspace.ext4"));
  if (native !== destination) await replaceArtifact(workspace, resolve(native, "empty-workspace.ext4"));

  const unsigned = {
    formatVersion: 2,
    id: "sandbox-minimal",
    version: "0.1.0",
    architecture: "x64",
    bootBundle: {
      kernel: { path: kernelName, sha256: kernelSha256 },
      bootstrap: {
        path: "minimal-bootstrap.ext4",
        sha256: sha256(await readFile(rootfs)),
        format: "ext4",
      },
      guestAgent: {
        version: "0.1.0",
        protocolMajor: guestProtocolMajor,
        protocolMinor: guestProtocolMinor,
        sha256: sha256(guestBytes),
      },
      capabilities: { overlayfs: true, vsock: true, seccomp: true, cgroupV2: true, devpts: true },
    },
    workload: {
      rootfs: {
        path: "minimal-workload.ext4",
        sha256: sha256(await readFile(workload)),
        format: "ext4",
      },
      stateTemplate: {
        path: "empty-workspace.ext4",
        sha256: sha256(await readFile(workspace)),
        format: "ext4",
      },
      defaults: {
        environment: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
        user: "agent",
        workingDirectory: "/workspace",
        entrypoint: [],
        command: [],
      },
      provenance: {
        kind: "source-built",
        sourceDigest: sha256(Buffer.concat([busyboxBytes, caBundle])),
      },
      compatibleProtocolMajor: guestProtocolMajor,
    },
  } as const;
  // Rust serializes the cleared optional signature as JSON null before canonical hashing.
  const identity = identityDigest({ ...unsigned, signature: null });
  let signature: string | null = null;
  if (releaseSeed !== undefined) {
    const privateKey = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), releaseSeed]),
      format: "der",
      type: "pkcs8",
    });
    const derivedPublicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
    if (derivedPublicKey !== releasePublicKey) throw new Error("the signing seed does not match the embedded release public key");
    signature = sign(null, Buffer.from(identity, "ascii"), privateKey).toString("hex");
  }
  const manifest = { ...unsigned, signature };
  await writeFile(resolve(destination, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
  if (explicitOutput === undefined) {
    await writeFile(resolve("packages/sandbox/images/manifest.json"), `${JSON.stringify({
      formatVersion: 1,
      buildId: "sandsurf-images-0.1.0",
      files: { "minimal-x64/manifest.json": sha256(Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)) },
    }, null, 2)}\n`, { mode: 0o644 });
  }
} finally {
  await rm(temporary, { recursive: true, force: true });
}

function isElf(bytes: Buffer): boolean {
  return bytes.length > 4 && bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
}

async function boundedRegularFile(path: string, maximum: number, label: string): Promise<Buffer> {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size === 0 || metadata.size > maximum || (metadata.mode & 0o022) !== 0) {
    throw new Error(`${label} must be a bounded, non-writable regular file`);
  }
  return readFile(path);
}

function assertStaticElf(path: string, label: string): Promise<void> {
  return new Promise((resolveCheck, rejectCheck) => {
    const output: Buffer[] = [];
    const child = spawn("readelf", ["--program-headers", path], { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
    child.once("error", rejectCheck);
    child.once("exit", (code, signal) => {
      if (code !== 0 || signal !== null) {
        rejectCheck(new Error(`${label} ELF inspection failed (${code ?? signal ?? "unknown"})`));
      } else if (Buffer.concat(output).toString("utf8").includes(" INTERP ")) {
        rejectCheck(new Error(`${label} must be statically linked`));
      } else {
        resolveCheck();
      }
    });
  });
}

async function createSparse(path: string, bytes: number): Promise<void> {
  const file = await open(path, "wx", 0o600);
  try {
    await file.truncate(bytes);
  } finally {
    await file.close();
  }
}

async function normalizeTimestamps(path: string): Promise<void> {
  if ((await stat(path)).isDirectory()) {
    for (const entry of await readdir(path)) await normalizeTimestamps(resolve(path, entry));
  }
  await utimes(path, 1_700_000_000, 1_700_000_000);
}

async function normalizeExt4(
  image: string,
  inodeCount: number,
  hashSeed: string,
  temporary: string,
  normalizeInodeTimes: boolean,
): Promise<void> {
  const commands = resolve(temporary, `debugfs-${hashSeed}.commands`);
  const lines = [`set_super_value hash_seed ${hashSeed}`];
  for (let inode = 1; inode <= inodeCount; inode += 1) {
    lines.push(`set_inode_field <${inode}> generation 0`);
    if (normalizeInodeTimes) {
      for (const field of ["atime", "ctime", "mtime", "crtime"]) {
        lines.push(`set_inode_field <${inode}> ${field} 1700000000`);
      }
      for (const field of ["atime_extra", "ctime_extra", "mtime_extra", "crtime_extra"]) {
        lines.push(`set_inode_field <${inode}> ${field} 0`);
      }
    }
  }
  await writeFile(commands, `${lines.join("\n")}\n`, { mode: 0o600 });
  await runQuiet("debugfs", ["-w", "-f", commands, image]);
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function replaceArtifact(source: string, destination: string): Promise<void> {
  const temporaryPath = `${destination}.new-${process.pid}`;
  await rm(temporaryPath, { force: true });
  try {
    await copyFile(source, temporaryPath, constants.COPYFILE_EXCL);
    await chmod(temporaryPath, 0o444);
    await rename(temporaryPath, destination);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

function identityDigest(value: unknown): string {
  const chunks: Buffer[] = [];
  putBytes(chunks, Buffer.from("SBX-DIGEST-1"));
  putBytes(chunks, Buffer.from("IDENTITY"));
  encodeCanonical(chunks, value);
  return sha256(Buffer.concat(chunks));
}

function encodeCanonical(chunks: Buffer[], value: unknown): void {
  if (value === null) { chunks.push(Buffer.from([0])); return; }
  if (typeof value === "boolean") { chunks.push(Buffer.from([1, value ? 1 : 0])); return; }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("canonical number is not a safe integer");
    const encoded = Buffer.alloc(10);
    encoded[0] = 2;
    encoded[1] = value >= 0 ? 0 : 1;
    if (value >= 0) encoded.writeBigUInt64BE(BigInt(value), 2);
    else encoded.writeBigInt64BE(BigInt(value), 2);
    chunks.push(encoded);
    return;
  }
  if (typeof value === "string") { chunks.push(Buffer.from([3])); putBytes(chunks, Buffer.from(value)); return; }
  if (Array.isArray(value)) {
    chunks.push(Buffer.from([4]), length(value.length));
    for (const entry of value) encodeCanonical(chunks, entry);
    return;
  }
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value).sort(([left], [right]) => Buffer.from(left).compare(Buffer.from(right)));
    chunks.push(Buffer.from([5]), length(entries.length));
    for (const [key, entry] of entries) { putBytes(chunks, Buffer.from(key)); encodeCanonical(chunks, entry); }
    return;
  }
  throw new Error("unsupported canonical value");
}

function putBytes(chunks: Buffer[], bytes: Buffer): void {
  chunks.push(length(bytes.length), bytes);
}

function length(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error("canonical length overflow");
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function run(
  command: string,
  args: readonly string[],
  cwd = process.cwd(),
  environment: Readonly<Record<string, string>> = {},
): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...environment }, stdio: "inherit" });
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}

function runQuiet(command: string, args: readonly string[]): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, E2FSPROGS_FAKE_TIME: "1700000000" },
    });
    const errors: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => errors.push(chunk));
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"}): ${Buffer.concat(errors).toString("utf8").slice(-4096)}`));
    });
  });
}
