import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { spawn } from "node:child_process";
import { packImageSources, writeImageIndex } from "./image-sources.ts";
import { prepare as prepareAlpineInputs } from "./prepare-alpine-inputs.ts";
import { alpinePackageOrigins, collectAlpineSources, publishAlpineSources, verifyAlpineSources } from "./alpine-sources.ts";

process.umask(0o022);

const buildProfile = process.env.SANDSURF_IMAGE_PROFILE ?? "debug";
if (buildProfile !== "debug" && buildProfile !== "release") throw new Error("SANDSURF_IMAGE_PROFILE must be debug or release");
const profileArguments = buildProfile === "release" ? ["--release"] : [];

const requestedArchitecture = process.env.SANDSURF_IMAGE_ARCHITECTURE
  ?? (process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : undefined);
if (requestedArchitecture !== "x64" && requestedArchitecture !== "arm64") {
  throw new Error("SANDSURF_IMAGE_ARCHITECTURE must be x64 or arm64");
}
const architecture = requestedArchitecture;
if (process.arch !== architecture) throw new Error("machine image assembly requires native Linux/KVM for its selected architecture");
const imageBuild = architecture === "x64" ? {
  rustTarget: "x86_64-unknown-linux-musl",
  alpineArchitecture: "x86_64",
  alpineSha256: "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677",
  elfMachine: 62,
} : {
  rustTarget: "aarch64-unknown-linux-musl",
  alpineArchitecture: "aarch64",
  alpineSha256: "9bf70a7f18ea44094cbb5f70c58f9af129c8214745743db0e68e5502cc2ce773",
  elfMachine: 183,
};
const guestTarget = process.env.SANDSURF_GUEST_RUST_TARGET ?? imageBuild.rustTarget;
if (![imageBuild.rustTarget, `${architecture === "x64" ? "x86_64" : "aarch64"}-unknown-linux-gnu`].includes(guestTarget)) throw new Error("guest target must be GNU or musl Linux for the selected image architecture");
const alpineVersion = "3.24.2";
const alpineSeries = "v3.24";
const alpineRepository = `https://dl-cdn.alpinelinux.org/alpine/${alpineSeries}`;
if (process.arch !== "x64" && process.arch !== "arm64") throw new Error("the guest image builder requires an x64 or arm64 host");
const kernelName = "boot-kernel";
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
const guestProtocolSource = await readFile(resolve("crates/sandsurf-protocol/src/ports.rs"), "utf8");
const guestProtocolMajor = Number(/GUEST_PROTOCOL_MAJOR: u16 = ([0-9]+);/u.exec(guestProtocolSource)?.[1]);
const guestProtocolMinor = Number(/GUEST_PROTOCOL_MINOR: u16 = ([0-9]+);/u.exec(guestProtocolSource)?.[1]);
if (!Number.isSafeInteger(guestProtocolMajor) || !Number.isSafeInteger(guestProtocolMinor)) throw new Error("guest protocol version is not declared");

if (process.platform !== "linux") {
  throw new Error("the guest image builder requires Linux");
}

const temporary = await mkdtemp(resolve(tmpdir(), "sandsurf-guest-image-"));
try {
  // A native CI build can supply a digest-bound management executable without
  // requiring the image assembler to execute or cross-compile target code.
  const binaryInput = process.env.SANDSURF_GUEST_BINARY_FILE;
  const binaryDigest = process.env.SANDSURF_GUEST_BINARY_SHA256;
  if (binaryInput === undefined && binaryDigest !== undefined) throw new Error("guest binary digest requires an explicit input file");
  if (binaryInput !== undefined && (!isAbsolute(binaryInput) || !/^[a-f0-9]{64}$/u.test(binaryDigest ?? ""))) {
    throw new Error("guest binary input requires an absolute file and its SHA-256 digest");
  }
  if (binaryInput === undefined) {
    await run("cargo", ["build", ...profileArguments, "-p", "sandsurf-guest", "--target", guestTarget], process.cwd(), {
      ...(guestTarget.endsWith("-musl") ? { [`CARGO_TARGET_${guestTarget.toUpperCase().replaceAll("-", "_")}_LINKER`]: "rust-lld" } : {}),
      [`CARGO_TARGET_${guestTarget.toUpperCase().replaceAll("-", "_")}_RUSTFLAGS`]: "-C target-feature=+crt-static",
    });
  }
  const guestInput = binaryInput ?? resolve("target", guestTarget, buildProfile, "sandsurf-guest");
  const inputBytes = await boundedRegularFile(guestInput, 128 * 1024 * 1024, "guest management executable");
  if (binaryInput !== undefined && sha256(inputBytes) !== binaryDigest) throw new Error("guest management input digest mismatch");
  const guestAgent = resolve(temporary, "sandsurf-management");
  await copyFile(guestInput, guestAgent);
  await run("strip", ["--strip-debug", guestAgent], process.cwd());
  const guestBytes = await boundedRegularFile(guestAgent, 128 * 1024 * 1024, "shipped management executable");
  assertElfArchitecture(guestBytes, "guest agent");
  const programOffset = Number(guestBytes.readBigUInt64LE(32));
  const programSize = guestBytes.readUInt16LE(54); const programCount = guestBytes.readUInt16LE(56);
  if (!Number.isSafeInteger(programOffset) || programSize < 56 || programCount > 128 || programOffset + programSize * programCount > guestBytes.length) throw new Error("guest agent program table is malformed");
  for (let index = 0; index < programCount; index++) {
    if (guestBytes.readUInt32LE(programOffset + index * programSize) === 3) throw new Error("guest management executable must be statically linked");
  }

  const system = resolve(temporary, "system.ext4");
  const systemMaterials = await buildLinuxSystem(temporary, system, guestAgent);

  const kernel = resolve(temporary, "boot/kernel");
  const initramfs = resolve(temporary, "boot/initramfs");
  const kernelSha256 = sha256(await boundedRegularFile(kernel, 128 * 1024 * 1024, "isolated kernel output"));
  const initramfsSha256 = sha256(await boundedRegularFile(initramfs, 256 * 1024 * 1024, "isolated initramfs output"));

  const explicitOutput = process.env.SANDSURF_IMAGE_OUTPUT_DIRECTORY;
  if (explicitOutput !== undefined && !isAbsolute(explicitOutput)) throw new Error("SANDSURF_IMAGE_OUTPUT_DIRECTORY must be absolute");
  const imageDirectory = `development-${architecture}`;
  const destination = explicitOutput ?? resolve("packages/sandsurf/images", imageDirectory);
  await mkdir(destination, { recursive: true });
  await replaceArtifact(kernel, resolve(destination, kernelName));
  await replaceArtifact(initramfs, resolve(destination, "boot-initramfs"));
  await replaceArtifact(system, resolve(destination, "system.ext4"));
  await publishAlpineSources(systemMaterials.sourceDirectory, resolve(destination, "source-materials"),
    systemMaterials.materials["alpine-corresponding-sources"]!, alpinePackageOrigins(systemMaterials.distribution));

  const unsigned = {
    formatVersion: 1,
    id: "sandsurf-development",
    version: alpineVersion,
    architecture,
    bootBundle: {
      kernel: { path: kernelName, sha256: kernelSha256 },
      initramfs: { path: "boot-initramfs", sha256: initramfsSha256 },
      profile: { kind: "alpine" },
      guestAgent: {
        version: "1.0.0",
        protocolMajor: guestProtocolMajor,
        protocolMinor: guestProtocolMinor,
        sha256: sha256(guestBytes),
      },
      capabilities: { overlayfs: true, vsock: true, seccomp: true, cgroupV2: true, devpts: true },
    },
    system: {
      cloneProfile: { kind: "alpine" },
      rootfs: {
        path: "system.ext4",
        sha256: await sha256BoundedFile(system, 8 * 1024 ** 3),
        format: "ext4",
      },
      defaults: {
        environment: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
        user: "agent",
        workingDirectory: "/home/agent",
      },
      provenance: {
        kind: "assembled",
        inputDigest: systemMaterials.inputDigest,
        materials: systemMaterials.materials,
        distribution: systemMaterials.distribution,
      },
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
    await writeImageIndex(resolve("packages/sandsurf/images"));
    await packImageSources(architecture);
  }
} finally {
  await rm(temporary, { recursive: true, force: true });
}

async function buildLinuxSystem(
  temporary: string,
  output: string,
  guestAgent: string,
): Promise<{ inputDigest: string; materials: Readonly<Record<string, string>>; distribution: unknown; sourceDirectory: string }> {
  if ((architecture === "x64" ? "x64" : "arm64") !== process.arch) {
    throw new Error("the isolated Alpine builder requires a Linux host of the target architecture");
  }
  const inputNames = ["SANDSURF_ALPINE_PACKAGES_ARCHIVE", "SANDSURF_ALPINE_PACKAGES_SHA256",
    "SANDSURF_ALPINE_PACKAGE_LOCK", "SANDSURF_ALPINE_PACKAGE_LOCK_SHA256"] as const;
  const supplied = inputNames.filter((name) => process.env[name] !== undefined);
  if (supplied.length !== 0 && supplied.length !== inputNames.length) {
    throw new Error("offline Alpine inputs require both files and both digests together");
  }
  const inputs = supplied.length === 0 ? await prepareAlpineInputs({
    architecture, output: resolve(temporary, "alpine-inputs"), temporaryDirectory: temporary,
  }) : process.env;
  const packages = inputs.SANDSURF_ALPINE_PACKAGES_ARCHIVE;
  const packageDigest = inputs.SANDSURF_ALPINE_PACKAGES_SHA256;
  const packageLock = inputs.SANDSURF_ALPINE_PACKAGE_LOCK;
  const lockDigest = inputs.SANDSURF_ALPINE_PACKAGE_LOCK_SHA256;
  if (packages === undefined || !isAbsolute(packages) || !/^[a-f0-9]{64}$/u.test(packageDigest ?? "") ||
      packageLock === undefined || !isAbsolute(packageLock) || !/^[a-f0-9]{64}$/u.test(lockDigest ?? "")) {
    throw new Error("offline build requires digest-pinned SANDSURF_ALPINE_PACKAGES_ARCHIVE and SANDSURF_ALPINE_PACKAGE_LOCK inputs with their SHA256 variables; packages must include linux-virt, mkinitfs and openssh");
  }
  const stagedPackages = resolve(temporary, "offline-apks.tar.gz");
  const stagedLock = resolve(temporary, "package-lock");
  await copyFile(packages, stagedPackages, constants.COPYFILE_EXCL);
  await copyFile(packageLock, stagedLock, constants.COPYFILE_EXCL);
  if (await sha256BoundedFile(stagedPackages, 1024 * 1024 * 1024) !== packageDigest ||
      await sha256BoundedFile(stagedLock, 1024 * 1024) !== lockDigest) {
    throw new Error("offline package inputs differ from their reviewed digests");
  }
  const targetArchive = resolve(temporary, "alpine-minirootfs.tar.gz");
  await run("curl", ["--fail", "--location", "--silent", "--show-error", "--output", targetArchive,
    `${alpineRepository}/releases/${imageBuild.alpineArchitecture}/alpine-minirootfs-${alpineVersion}-${imageBuild.alpineArchitecture}.tar.gz`]);
  if (sha256(await readFile(targetArchive)) !== imageBuild.alpineSha256) throw new Error("Alpine root digest mismatch");
  // Only reviewed recipe files enter this host tree. Neither the distribution
  // archive nor package contents are unpacked or executed by the host.
  const overlay = resolve(temporary, "recipe");
  await mkdir(resolve(overlay, "usr/sbin"), { recursive: true });
  await copyFile(guestAgent, resolve(overlay, "usr/sbin/sandsurf-guest"));
  await chmod(resolve(overlay, "usr/sbin/sandsurf-guest"), 0o755);
  const recipePaths = ["etc/inittab", "etc/fstab", "etc/network/interfaces", "etc/init.d/sandsurf-management", "etc/init.d/sandsurf-expand-root",
    "etc/init.d/sandsurf-clone-identity", "etc/sudoers.d/agent", "etc/apk/commit_hooks.d/sandsurf-boot",
    "usr/sbin/sandsurf-select-boot", "sandsurf-build.sh"];
  for (const path of recipePaths) {
    const destination = resolve(overlay, path);
    await mkdir(resolve(destination, ".."), { recursive: true });
    await copyFile(resolve("scripts/guest-image", path), destination);
    await chmod(destination, path === "sandsurf-build.sh" || path.startsWith("usr/") || path.includes("init.d/") || path.includes("commit_hooks.d/") ? 0o755 : path.includes("sudoers") ? 0o440 : 0o644);
  }
  await copyFile(stagedLock, resolve(overlay, "expected-package-lock"));
  const archive = resolve(temporary, "recipe.tar");
  await run("cargo", ["run", "--locked", ...profileArguments, "-p", "sandsurf-image", "--example", "archive_system", "--", overlay, archive]);
  await run("cargo", ["run", "--locked", ...profileArguments, "-p", "sandsurf-image", "--example", "build_alpine", "--",
    targetArchive, stagedPackages, archive, output, resolve(temporary, "boot")]);
  const recipe = Object.fromEntries(await Promise.all(recipePaths.map(async (path) => [path, sha256(await readFile(resolve("scripts/guest-image", path)))])));
  const helperSources = ["crates/sandsurf-image/examples/producer/mod.rs", "crates/sandsurf-image/src/boot.rs", "crates/sandsurf-image/src/packages.rs", "crates/sandsurf-image/examples/build_alpine.rs"];
  const helperRecipe = Object.fromEntries(await Promise.all(helperSources.map(async (path) => [path, sha256(await readFile(resolve(path)))])));
  const distribution: unknown = JSON.parse((await boundedRegularFile(resolve(temporary, "boot/distribution.json"), 1024 * 1024, "installed package provenance")).toString("utf8"));
  const cachedSources = process.env.SANDSURF_ALPINE_SOURCE_DIRECTORY;
  const cachedDigest = process.env.SANDSURF_ALPINE_SOURCE_SHA256;
  if ((cachedSources === undefined) !== (cachedDigest === undefined) ||
      cachedSources !== undefined && (!isAbsolute(cachedSources) || !/^[a-f0-9]{64}$/u.test(cachedDigest!))) {
    throw new Error("corresponding source inputs require an absolute directory and its inventory SHA256 together");
  }
  const sourceDirectory = cachedSources ?? resolve(temporary, "source-materials");
  const correspondingSources = cachedDigest ?? await collectAlpineSources(sourceDirectory, alpinePackageOrigins(distribution));
  await verifyAlpineSources(sourceDirectory, correspondingSources, alpinePackageOrigins(distribution));
  const materials = {
    "alpine-minirootfs": imageBuild.alpineSha256,
    "alpine-offline-packages": packageDigest!,
    "alpine-package-lock": lockDigest!,
    "sandsurf-system-recipe": identityDigest(recipe),
    "sandsurf-appliance-recipe": identityDigest(helperRecipe),
    "sandsurf-management": sha256(await readFile(guestAgent)),
    "alpine-installed-database": await sha256BoundedFile(resolve(temporary, "boot/package-database"), 4 * 1024 * 1024),
    "alpine-corresponding-sources": correspondingSources,
  };
  return { inputDigest: identityDigest(materials), materials, distribution, sourceDirectory };
}

function assertElfArchitecture(bytes: Buffer, label: string): void {
  if (bytes.length < 20 || !bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
      bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== imageBuild.elfMachine) {
    throw new Error(`${label} is not a little-endian 64-bit ${architecture} ELF executable`);
  }
}

async function boundedRegularFile(
  path: string,
  maximum: number,
  label: string,
  allowWritable = false,
): Promise<Buffer> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size === 0 || metadata.size > maximum || (!allowWritable && (metadata.mode & 0o022) !== 0)) {
    throw new Error(`${label} must be a bounded, non-writable regular file`);
  }
  return readFile(path);
}

async function sha256BoundedFile(path: string, maximum: number): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0 || metadata.size > maximum) {
    throw new Error("image input is not a bounded regular file");
  }
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    bytes += chunk.length;
    if (bytes > maximum) throw new Error("image input grew beyond bound");
    hash.update(chunk);
  }
  if (bytes !== metadata.size) throw new Error("image input changed length");
  return hash.digest("hex");
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
  putBytes(chunks, Buffer.from("SANDSURF-COMPUTER-DIGEST-1"));
  putBytes(chunks, Buffer.from("IDENTITY"));
  encodeCanonical(chunks, value);
  return sha256(Buffer.concat(chunks));
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
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
  captureOutput = false,
): Promise<string> {
  return new Promise((resolveRun, rejectRun) => {
    let output = "";
    const child = spawn(command, args, { cwd, env: { ...process.env, ...environment }, stdio: captureOutput ? ["ignore", "pipe", "inherit"] : "inherit" });
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
      if (output.length > 4096) { child.kill(); rejectRun(new Error(`${command} exceeded its build-output bound`)); }
    });
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (code === 0) resolveRun(output);
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}
