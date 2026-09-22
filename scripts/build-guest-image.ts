import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  lutimes,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { spawn } from "node:child_process";
import { packImageSources } from "./image-sources.ts";

process.umask(0o022);

const requestedArchitecture = process.env.SANDSURF_IMAGE_ARCHITECTURE
  ?? (process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : undefined);
if (requestedArchitecture !== "x64" && requestedArchitecture !== "arm64") {
  throw new Error("SANDSURF_IMAGE_ARCHITECTURE must be x64 or arm64");
}
const architecture = requestedArchitecture;
const imageBuild = architecture === "x64" ? {
  rustTarget: "x86_64-unknown-linux-musl",
  kernelArchitecture: "x86_64",
  kernelSha256: "645688b5933cb257f7d4fa71eb246669233e8c2db8378217c99cf891541fe3d5",
  kernelConfigSha256: "c9779a5f7e89c91e371c0a4d15134f46a4cdf2fce6239261edb5c169baec3f2d",
  alpineArchitecture: "x86_64",
  alpineSha256: "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677",
  elfMachine: 62,
} : {
  rustTarget: "aarch64-unknown-linux-musl",
  kernelArchitecture: "aarch64",
  kernelSha256: "b2054e82c9d1120519882c39485a17b29657b77c93ed8c9d412996de6ba9711c",
  kernelConfigSha256: "4307633ad8dbe3726f36dc11aca9d1eda8c8f2c8a28cdb9888fcfcc3648e409b",
  alpineArchitecture: "aarch64",
  alpineSha256: "9bf70a7f18ea44094cbb5f70c58f9af129c8214745743db0e68e5502cc2ce773",
  elfMachine: 183,
};
const alpineVersion = "3.24.2";
const alpineSeries = "v3.24";
const alpineRepository = `https://dl-cdn.alpinelinux.org/alpine/${alpineSeries}`;
const alpineToolSha256 = "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677";
const expectedAlpinePackages = [
  "alpine-baselayout-data=3.7.2-r1", "alpine-baselayout=3.7.2-r1", "alpine-keys=2.6-r0",
  "alpine-release=3.24.2-r0", "apk-tools=3.0.8-r0", "brotli-libs=1.2.0-r1",
  "busybox-binsh=1.37.0-r31", "busybox-extras=1.37.0-r31", "busybox=1.37.0-r31", "c-ares=1.34.8-r0",
  "ca-certificates-bundle=20260909-r0", "ca-certificates=20260909-r0",
  "git-init-template=2.54.0-r0", "git=2.54.0-r0", "libapk=3.0.8-r0",
  "libcrypto3=3.5.8-r0", "libcurl=8.22.0-r0", "libexpat=2.8.4-r0",
  "libidn2=2.3.8-r0", "libpsl=0.21.5-r3", "libssl3=3.5.8-r0",
  "libunistring=1.4.2-r0", "musl-utils=1.2.6-r2", "musl=1.2.6-r2",
  "nghttp2-libs=1.69.0-r0", "pcre2=10.48-r0", "scanelf=1.3.9-r1",
  "ssl_client=1.37.0-r31", "zlib=1.3.2-r0", "zstd-libs=1.5.7-r2",
] as const;
const kernelName = "vmlinux-6.18.41";
const kernelBaseUrl = `https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260819-0a745def42dd-0/${imageBuild.kernelArchitecture}`;
const kernelUrl = `${kernelBaseUrl}/${kernelName}`;
const kernelSha256 = imageBuild.kernelSha256;
const kernelConfigUrl = `${kernelUrl}.config`;
const kernelConfigSha256 = imageBuild.kernelConfigSha256;
const hypervKernelSha256 = "bdb750c617bf47fc893c9ee849e82b4b3bc0287d693195b58bd3fa1c4c8936b5";
const localBuild = process.env.SANDSURF_LOCAL_IMAGE === "1";
const signingKeyPath = process.env.SANDSURF_IMAGE_SIGNING_KEY_FILE;
let releaseSeed: Buffer | undefined;
if (!localBuild) {
  if (signingKeyPath === undefined || !isAbsolute(signingKeyPath)) {
    throw new Error("SANDSURF_IMAGE_SIGNING_KEY_FILE must name an absolute file containing a 32-byte Ed25519 seed");
  }
  const signingKeyMetadata = await stat(signingKeyPath);
  if (!signingKeyMetadata.isFile() || (signingKeyMetadata.mode & 0o077) !== 0) {
    throw new Error("the image signing seed must be a private regular file");
  }
  releaseSeed = await readFile(signingKeyPath);
  if (releaseSeed.byteLength !== 32) throw new Error("the image signing seed must contain exactly 32 bytes");
}
const releasePublicKey = "495b4a26a65df66f7090065ed23a30a29ad3b53e0ed90d6506a2d6c8c0aba684";
const guestProtocolSource = await readFile(resolve("crates/sandbox-guest/src/lib.rs"), "utf8");
const guestProtocolMajor = Number(/GUEST_PROTOCOL_MAJOR: u16 = ([0-9]+);/u.exec(guestProtocolSource)?.[1]);
const guestProtocolMinor = Number(/GUEST_PROTOCOL_MINOR: u16 = ([0-9]+);/u.exec(guestProtocolSource)?.[1]);
if (!Number.isSafeInteger(guestProtocolMajor) || !Number.isSafeInteger(guestProtocolMinor)) throw new Error("guest protocol version is not declared");

if (process.platform !== "linux") {
  throw new Error("the guest image builder requires Linux");
}

const temporary = await mkdtemp(resolve(tmpdir(), "sandbox-guest-image-"));
try {
  await run("cargo", ["build", "--release", "-p", "sandbox-guest", "--target", imageBuild.rustTarget], process.cwd(), {
    [`CARGO_TARGET_${imageBuild.rustTarget.toUpperCase().replaceAll("-", "_")}_LINKER`]: "rust-lld",
  });
  const guestAgent = resolve("target", imageBuild.rustTarget, "release/sandbox-guest");
  const guestBytes = await readFile(guestAgent);
  assertElfArchitecture(guestBytes, "guest agent");

  const root = resolve(temporary, "bootstrap");
  for (const path of [
    "dev", "proc", "run", "sandsurf/control", "sandsurf/lower", "sandsurf/state",
    "sandsurf/workload", "sbin", "sys/fs/cgroup", "tmp",
  ]) {
    await mkdir(resolve(root, path), { recursive: true });
  }
  await copyFile(guestAgent, resolve(root, "sbin/sandbox-guest"));
  await chmod(resolve(root, "sbin/sandbox-guest"), 0o755);
  await normalizeTimestamps(root);

  const rootfs = resolve(temporary, "trusted-bootstrap.ext4");
  await materializeTree(root, rootfs, 128 * 1024 * 1024, temporary, "trusted-bootstrap");
  const workload = resolve(temporary, "development-workload.ext4");
  const workloadMaterials = await buildDevelopmentWorkload(temporary, workload);
  const workspace = resolve(temporary, "empty-workspace.ext4");
  const empty = resolve(temporary, "empty");
  await mkdir(empty);
  await normalizeTimestamps(empty);
  await materializeTree(empty, workspace, 128 * 1024 * 1024, temporary, "empty-workspace");

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
  const imageDirectory = `development-${architecture}`;
  const destination = explicitOutput ?? resolve("packages/sandbox/images", imageDirectory);
  await mkdir(destination, { recursive: true });
  for (const retired of ["minimal-rootfs.ext4", "minimal-workload.ext4", "vmlinux-6.1.177"]) {
    await rm(resolve(destination, retired), { force: true });
  }
  await replaceArtifact(kernel, resolve(destination, kernelName));
  await replaceArtifact(rootfs, resolve(destination, "trusted-bootstrap.ext4"));
  await replaceArtifact(workload, resolve(destination, "development-workload.ext4"));
  await replaceArtifact(workspace, resolve(destination, "empty-workspace.ext4"));

  let platformArtifacts: Record<string, unknown> = {};
  if (architecture === "x64") {
    const hypervKernelSource = process.env.SANDSURF_HYPERV_KERNEL_FILE
      ?? resolve("packages/sandbox/image-build-inputs/x64/hyperv-vmlinuz-6.18.41");
    if (!isAbsolute(hypervKernelSource)) {
      throw new Error("SANDSURF_HYPERV_KERNEL_FILE must be absolute");
    }
    const hypervKernel = resolve(destination, "hyperv-vmlinuz-6.18.41");
    if (resolve(hypervKernelSource) !== hypervKernel) {
      await replaceArtifact(hypervKernelSource, hypervKernel);
    }
    const hypervKernelBytes = await boundedRegularFile(
      hypervKernel,
      128 * 1024 * 1024,
      "Hyper-V kernel",
      true,
    );
    if (sha256(hypervKernelBytes) !== hypervKernelSha256) {
      throw new Error("Hyper-V kernel digest mismatch; rebuild it with npm run build:hyperv-kernel");
    }
    assertElfOrBzImage(hypervKernelBytes, "Hyper-V kernel");
    const qemuImg = process.env.SANDSURF_QEMU_IMG ?? "qemu-img";
    const conversions = [
      [rootfs, resolve(destination, "trusted-bootstrap.vhdx")],
      [workload, resolve(destination, "development-workload.vhdx")],
      [workspace, resolve(destination, "empty-workspace.vhdx")],
    ] as const;
    for (const [source, output] of conversions) {
      const staging = `${output}.new-${process.pid}`;
      await rm(staging, { force: true });
      try {
        await run(qemuImg, [
          "convert", "-f", "raw", "-O", "vhdx",
          "-o", "subformat=dynamic,block_size=1048576",
          source, staging,
        ]);
        await chmod(staging, 0o444);
        await rename(staging, output);
      } finally {
        await rm(staging, { force: true });
      }
    }
    platformArtifacts = {
      windowsX64: {
        kernel: { path: "hyperv-vmlinuz-6.18.41", sha256: sha256(hypervKernelBytes) },
        bootstrap: { path: "trusted-bootstrap.vhdx", sha256: sha256(await readFile(conversions[0][1])) },
        workload: { path: "development-workload.vhdx", sha256: sha256(await readFile(conversions[1][1])) },
        stateTemplate: { path: "empty-workspace.vhdx", sha256: sha256(await readFile(conversions[2][1])) },
      },
    };
  }

  const unsigned = {
    formatVersion: 2,
    id: "sandsurf-development",
    version: alpineVersion,
    architecture,
    bootBundle: {
      kernel: { path: kernelName, sha256: kernelSha256 },
      bootstrap: {
        path: "trusted-bootstrap.ext4",
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
        path: "development-workload.ext4",
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
        sourceDigest: workloadMaterials.sourceDigest,
        materials: workloadMaterials.materials,
      },
      compatibleProtocolMajor: guestProtocolMajor,
    },
    platformArtifacts,
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
    await writeImageIndex(resolve("packages/sandbox/images"));
    await packImageSources(architecture);
  }
} finally {
  await rm(temporary, { recursive: true, force: true });
}

async function buildDevelopmentWorkload(
  temporary: string,
  output: string,
): Promise<{ sourceDigest: string; materials: Readonly<Record<string, string>> }> {
  const targetArchive = resolve(temporary, `alpine-minirootfs-${alpineVersion}-${imageBuild.alpineArchitecture}.tar.gz`);
  const toolArchive = resolve(temporary, `alpine-minirootfs-${alpineVersion}-x86_64.tar.gz`);
  const targetUrl = `${alpineRepository}/releases/${imageBuild.alpineArchitecture}/alpine-minirootfs-${alpineVersion}-${imageBuild.alpineArchitecture}.tar.gz`;
  const toolUrl = `${alpineRepository}/releases/x86_64/alpine-minirootfs-${alpineVersion}-x86_64.tar.gz`;
  await run("curl", ["--fail", "--location", "--silent", "--show-error", "--output", targetArchive, targetUrl]);
  if (sha256(await readFile(targetArchive)) !== imageBuild.alpineSha256) {
    throw new Error("Alpine development root digest mismatch");
  }
  if (targetArchive !== toolArchive) {
    await run("curl", ["--fail", "--location", "--silent", "--show-error", "--output", toolArchive, toolUrl]);
  }
  if (sha256(await readFile(toolArchive)) !== alpineToolSha256) {
    throw new Error("Alpine package-tool root digest mismatch");
  }

  const workloadRoot = resolve(temporary, "development-root");
  const toolRoot = resolve(temporary, "apk-tool-root");
  await mkdir(workloadRoot);
  await mkdir(toolRoot);
  for (const [archive, destination] of [[targetArchive, workloadRoot], [toolArchive, toolRoot]] as const) {
    await run("tar", [
      "--extract", "--gzip", "--file", archive, "--directory", destination,
      "--no-same-owner",
    ]);
  }
  const apk = resolve(toolRoot, "sbin/apk");
  const loader = resolve(toolRoot, "lib/ld-musl-x86_64.so.1");
  await run(loader, [
    "--library-path", `${resolve(toolRoot, "lib")}:${resolve(toolRoot, "usr/lib")}`,
    apk,
    "--root", workloadRoot,
    "--arch", imageBuild.alpineArchitecture,
    "--no-cache",
    "--no-scripts",
    "--repository", `${alpineRepository}/main`,
    "--repository", `${alpineRepository}/community`,
    "add",
    "ca-certificates=20260909-r0",
    "busybox-extras=1.37.0-r31",
    "git=2.54.0-r0",
  ]);

  const installed = await readFile(resolve(workloadRoot, "lib/apk/db/installed"), "utf8");
  const packages = parseInstalledPackages(installed);
  if (JSON.stringify(packages) !== JSON.stringify([...expectedAlpinePackages].sort())) {
    throw new Error("installed Alpine package closure differs from the reviewed development image lock");
  }
  for (const [relative, label] of [
    ["bin/busybox", "BusyBox"],
    ["bin/busybox-extras", "BusyBox extras"],
    ["sbin/apk", "apk"],
    ["usr/bin/git", "Git"],
  ] as const) {
    const bytes = await boundedRegularFile(resolve(workloadRoot, relative), 64 * 1024 * 1024, label, true);
    assertElfArchitecture(bytes, label);
  }
  const caBundle = await boundedRegularFile(
    resolve(workloadRoot, "etc/ssl/certs/ca-certificates.crt"),
    4 * 1024 * 1024,
    "Alpine CA bundle",
    true,
  );
  if (caBundle.includes(0) || !caBundle.includes(Buffer.from("-----BEGIN CERTIFICATE-----", "ascii"))) {
    throw new Error("Alpine CA bundle is not a PEM certificate bundle");
  }
  await appendAccount(resolve(workloadRoot, "etc/passwd"), "agent", "agent:x:1000:1000:agent:/home/agent:/bin/sh");
  await appendAccount(resolve(workloadRoot, "etc/group"), "agent", "agent:x:1000:");
  await normalizeTimestamps(workloadRoot);

  const canonicalTar = resolve(temporary, "development-root.tar");
  await run("tar", [
    "--create", "--file", canonicalTar,
    "--format=gnu", "--sort=name", "--mtime=@1700000000",
    "--owner=0", "--group=0", "--numeric-owner",
    "--directory", workloadRoot, ".",
  ]);
  const agentRoot = resolve(temporary, "agent-directories");
  await mkdir(resolve(agentRoot, "home/agent"), { recursive: true, mode: 0o775 });
  await mkdir(resolve(agentRoot, "workspace"), { mode: 0o775 });
  await normalizeTimestamps(agentRoot);
  await run("tar", [
    "--append", "--file", canonicalTar,
    "--format=gnu", "--sort=name", "--mtime=@1700000000",
    "--owner=1000", "--group=1000", "--numeric-owner",
    "--directory", agentRoot, "home/agent", "workspace",
  ]);
  await run("cargo", [
    "run", "--locked", "--release", "-p", "sandbox-image", "--example", "materialize_ext4", "--",
    canonicalTar, output, String(128 * 1024 * 1024),
  ]);

  const packageLock = Buffer.from(`${packages.join("\n")}\n`, "utf8");
  const builderIdentity = Buffer.from("arcbox-ext4-0.1.2+sandsurf-deterministic-v2", "utf8");
  return {
    sourceDigest: sha256(Buffer.concat([await readFile(targetArchive), packageLock, builderIdentity])),
    materials: {
      "alpine-minirootfs": imageBuild.alpineSha256,
      "alpine-packages": sha256(packageLock),
      "sandsurf-ext4-builder": sha256(builderIdentity),
    },
  };
}

function parseInstalledPackages(database: string): string[] {
  const packages: string[] = [];
  for (const record of database.split("\n\n")) {
    const name = /^P:(.+)$/mu.exec(record)?.[1];
    const version = /^V:(.+)$/mu.exec(record)?.[1];
    if (name !== undefined && version !== undefined) packages.push(`${name}=${version}`);
  }
  return packages.sort();
}

async function appendAccount(path: string, name: string, record: string): Promise<void> {
  const current = await readFile(path, "utf8");
  if (current.split("\n").some((line) => line.startsWith(`${name}:`))) {
    throw new Error(`Alpine development root already defines ${name}`);
  }
  await writeFile(path, `${current.endsWith("\n") ? current : `${current}\n`}${record}\n`, { mode: 0o644 });
}

function assertElfArchitecture(bytes: Buffer, label: string): void {
  if (bytes.length < 20 || !bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
      bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== imageBuild.elfMachine) {
    throw new Error(`${label} is not a little-endian 64-bit ${architecture} ELF executable`);
  }
}

function assertElfOrBzImage(bytes: Buffer, label: string): void {
  const elf = bytes.length >= 4 && bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  const bzImage = bytes.length >= 0x206 && bytes.subarray(0x202, 0x206).toString("ascii") === "HdrS";
  if (!elf && !bzImage) throw new Error(`${label} is neither an ELF kernel nor an x86 bzImage`);
}

async function writeImageIndex(root: string): Promise<void> {
  const files: Record<string, string> = {};
  for (const name of (await readdir(root)).sort()) {
    if (!/^development-(x64|arm64)$/u.test(name)) continue;
    const path = resolve(root, name, "manifest.json");
    try {
      files[`${name}/manifest.json`] = sha256(await readFile(path));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  if (Object.keys(files).length === 0) throw new Error("no guest image manifests were built");
  await writeFile(resolve(root, "manifest.json"), `${JSON.stringify({
    formatVersion: 1,
    buildId: "sandsurf-images-0.1.0",
    files,
  }, null, 2)}\n`, { mode: 0o644 });
}

async function boundedRegularFile(
  path: string,
  maximum: number,
  label: string,
  allowWritable = false,
): Promise<Buffer> {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size === 0 || metadata.size > maximum || (!allowWritable && (metadata.mode & 0o022) !== 0)) {
    throw new Error(`${label} must be a bounded, non-writable regular file`);
  }
  return readFile(path);
}

async function normalizeTimestamps(path: string): Promise<void> {
  const metadata = await lstat(path);
  if (metadata.isDirectory()) {
    for (const entry of await readdir(path)) await normalizeTimestamps(resolve(path, entry));
  }
  if (metadata.isSymbolicLink()) await lutimes(path, 1_700_000_000, 1_700_000_000);
  else await utimes(path, 1_700_000_000, 1_700_000_000);
}

async function materializeTree(
  root: string,
  image: string,
  bytes: number,
  temporary: string,
  label: string,
): Promise<void> {
  const archive = resolve(temporary, `${label}.tar`);
  await run("tar", [
    "--create", "--file", archive,
    "--format=gnu", "--sort=name", "--mtime=@1700000000",
    "--owner=0", "--group=0", "--numeric-owner",
    "--directory", root, ".",
  ]);
  await run("cargo", [
    "run", "--locked", "--release", "-p", "sandbox-image", "--example", "materialize_ext4", "--",
    archive, image, String(bytes),
  ]);
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
