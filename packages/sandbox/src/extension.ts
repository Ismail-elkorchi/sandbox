import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { array, boolean, digest, number, object, string } from "./validation.js";
import { SandboxRuntimeIntegrityError, SandboxUnsupportedError } from "./errors.js";

export interface SandboxImageReference {
  manifestPath: string;
  trust: "bundled" | "explicit-local";
  digest?: string;
}

export interface SandboxExtensionRegistration {
  readonly kind: "hardware-vm";
  readonly descriptorPath: string;
  readonly descriptorDigest: string;
}

export interface VerifiedSandboxExtension {
  readonly kind: "hardware-vm";
  readonly runtimePath: string;
  readonly runtimeDigest: string;
  readonly descriptorDigest: string;
  readonly explicitLocalImages: boolean;
  readonly bundledImageManifestDigests: readonly string[];
}

export async function verifyExtension(
  registration: SandboxExtensionRegistration,
): Promise<VerifiedSandboxExtension> {
  if (!isAbsolute(registration.descriptorPath)) {
    throw integrity("extension descriptor path must be absolute");
  }
  const descriptorBytes = await readFile(registration.descriptorPath).catch(() => {
    throw integrity("extension descriptor is missing");
  });
  const descriptorDigest = createHash("sha256").update(descriptorBytes).digest("hex");
  if (digest(registration.descriptorDigest, "extension descriptor digest") !== descriptorDigest) {
    throw integrity("extension descriptor digest mismatch");
  }
  const descriptor = object(JSON.parse(descriptorBytes.toString("utf8")), "extension descriptor");
  if (number(descriptor.formatVersion, "extension formatVersion") !== 1) throw integrity("unsupported extension descriptor version");
  if (string(descriptor.kind, "extension kind") !== registration.kind) throw integrity("extension kind mismatch");
  const protocol = object(descriptor.protocol, "extension protocol");
  const minimum = number(protocol.minimumMajor, "extension minimum protocol");
  const maximum = number(protocol.maximumMajor, "extension maximum protocol");
  if (minimum > 1 || maximum < 1) throw new SandboxUnsupportedError({
    code: "unsupported.extension_protocol",
    message: "hardware-VM extension does not support protocol major 1",
    phase: "validate",
    targetExecuted: false,
  });
  const hosts = array(descriptor.hosts, "extension hosts");
  const supported = hosts.some((entry) => {
    const host = object(entry, "extension host");
    return string(host.platform, "extension host platform") === process.platform
      && string(host.architecture, "extension host architecture") === process.arch;
  });
  if (!supported) throw new SandboxUnsupportedError({
    code: "unsupported.extension_host",
    message: `hardware-VM extension does not support ${process.platform}-${process.arch}`,
    phase: "validate",
    targetExecuted: false,
  });
  const runtime = object(descriptor.runtime, "extension runtime");
  const descriptorDirectory = dirname(registration.descriptorPath);
  const runtimePath = resolveBeneath(descriptorDirectory, string(runtime.path, "extension runtime path"));
  const runtimeDigest = digest(runtime.sha256, "extension runtime digest");
  await verifyRegularFile(runtimePath, runtimeDigest);
  const imageTrust = object(descriptor.imageTrust, "extension image trust");
  return {
    kind: "hardware-vm",
    runtimePath,
    runtimeDigest,
    descriptorDigest,
    explicitLocalImages: boolean(imageTrust.explicitLocal, "extension explicit-local image trust"),
    bundledImageManifestDigests: array(
      imageTrust.bundledManifestDigests,
      "extension bundled image digests",
    ).map((value) => digest(value, "extension bundled image digest")),
  };
}

async function verifyRegularFile(path: string, expectedDigest: string): Promise<void> {
  const metadata = await lstat(path).catch(() => {
    throw integrity("extension runtime is missing");
  });
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || (process.platform !== "win32" && (metadata.mode & 0o022) !== 0)
  ) {
    throw integrity("extension runtime must be a non-symbolic regular file with safe host permissions");
  }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await file.stat();
    if (opened.dev !== metadata.dev || opened.ino !== metadata.ino) throw integrity("extension runtime changed while opening");
    const actual = createHash("sha256").update(await file.readFile()).digest("hex");
    if (actual !== expectedDigest) throw integrity("extension runtime digest mismatch");
  } finally {
    await file.close();
  }
}

function resolveBeneath(parent: string, child: string): string {
  if (isAbsolute(child)) throw integrity("extension paths must be descriptor-relative");
  const resolved = resolve(parent, child);
  const remainder = relative(parent, resolved);
  if (remainder === "" || remainder.startsWith("..") || isAbsolute(remainder)) {
    throw integrity("extension path escapes its descriptor directory");
  }
  return resolved;
}

function integrity(message: string): SandboxRuntimeIntegrityError {
  return new SandboxRuntimeIntegrityError({
    code: "runtime_integrity.extension",
    message,
    phase: "validate",
    targetExecuted: false,
  });
}
