import { readFile, writeFile } from "node:fs/promises";
import { sha256File } from "../packages/sandsurf/src/file-integrity.ts";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

interface CargoPackage {
  id: string;
  name: string;
  version: string;
  license: string;
  external: boolean;
}

interface CargoNode {
  id: string;
  dependencies: readonly string[];
}

type ComponentLicense = { expression: string } | { license: { id: string } };

interface Component {
  type: string;
  name: string;
  version: string;
  licenses: readonly ComponentLicense[];
  purl?: string;
  hashes?: readonly { alg: string; content: string }[];
}

const metadataValue: unknown = JSON.parse(await capture("cargo", ["metadata", "--locked", "--format-version", "1"]));
const metadata = parseMetadata(metadataValue);
const packages = new Map(metadata.packages.map((package_) => [package_.id, package_]));
const nodes = new Map(metadata.nodes.map((node) => [node.id, node]));

const nativeRoot = resolve("packages/sandsurf/native");
const nativeManifest: unknown = JSON.parse(await readFile(resolve(nativeRoot, "manifest.json"), "utf8"));
if (!isRecord(nativeManifest) || !isRecord(nativeManifest.files)) throw new Error("invalid native manifest");
const nativeComponents: Component[] = [];
for (const [path, expected] of Object.entries(nativeManifest.files)) {
  const match = /^linux-(x64|arm64)\/firecracker-v([0-9]+\.[0-9]+\.[0-9]+)-(x86_64|aarch64)$/u.exec(path);
  if (match === null) continue;
  const architecture = match[1]!;
  if ((architecture === "x64") !== (match[3] === "x86_64")) throw new Error("Firecracker architecture mismatch");
  const actual = await sha256File(resolve(nativeRoot, path), 512 * 1024 ** 2);
  if (expected !== actual) throw new Error(`native supply-chain digest mismatch: ${path}`);
  nativeComponents.push({
    type: "application",
    name: "firecracker",
    version: match[2]!,
    purl: `pkg:generic/firecracker@${match[2]}?arch=${architecture}`,
    licenses: [{ license: { id: "Apache-2.0" } }],
    hashes: [{ alg: "SHA-256", content: actual }],
  });
}
await generate(["sandsurf-host", "sandsurf-guest"], "sandsurf", resolve("packages/sandsurf"), nativeComponents);

async function generate(rootNames: readonly string[], npmName: string, destination: string, additional: readonly Component[]): Promise<void> {
  const roots = rootNames.map((rootName) => {
    const root = metadata.packages.find((package_) => package_.name === rootName);
    if (root === undefined) throw new Error(`missing cargo package ${rootName}`);
    return root.id;
  });
  const identifiers = closure(roots);
  const dependencyComponents: Component[] = [...identifiers]
    .map((identifier) => packages.get(identifier))
    .filter((package_): package_ is CargoPackage => package_?.external === true)
    .map((package_): Component => ({
      type: "library",
      name: package_.name,
      version: package_.version,
      licenses: [{ expression: package_.license }],
      purl: `pkg:cargo/${package_.name}@${package_.version}`,
    }));
  const components = [...dependencyComponents, ...additional]
    .sort((left, right) => left.name.localeCompare(right.name));
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: { component: { type: "application", name: npmName, version: "1.0.0" } },
    components,
  };
  await writeFile(resolve(destination, "SBOM.cdx.json"), `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o644 });
  const notices = components
    .map((component) => `${component.name} ${component.version}\t${licenseText(component.licenses[0])}`)
    .join("\n");
  await writeFile(resolve(destination, "THIRD-PARTY"), `Third-party components\n\n${notices}\n`, { mode: 0o644 });
}

function closure(roots: readonly string[]): Set<string> {
  const visited = new Set<string>();
  const pending = [...roots];
  while (pending.length > 0) {
    const identifier = pending.pop();
    if (identifier === undefined || visited.has(identifier)) continue;
    visited.add(identifier);
    const node = nodes.get(identifier);
    if (node !== undefined) pending.push(...node.dependencies);
  }
  return visited;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseMetadata(value: unknown): { packages: readonly CargoPackage[]; nodes: readonly CargoNode[] } {
  if (!isRecord(value) || !isUnknownArray(value.packages) || !isRecord(value.resolve) || !isUnknownArray(value.resolve.nodes)) {
    throw new Error("cargo metadata returned an invalid dependency graph");
  }
  return {
    packages: value.packages.map((entry) => {
      if (!isRecord(entry)) throw new Error("cargo metadata package is invalid");
      return {
        id: requiredString(entry.id, "package id"),
        name: requiredString(entry.name, "package name"),
        version: requiredString(entry.version, "package version"),
        license: typeof entry.license === "string" ? entry.license : "UNKNOWN",
        external: entry.source !== null,
      };
    }),
    nodes: value.resolve.nodes.map((entry) => {
      if (!isRecord(entry) || !isStringArray(entry.dependencies)) {
        throw new Error("cargo metadata dependency node is invalid");
      }
      return { id: requiredString(entry.id, "node id"), dependencies: entry.dependencies };
    }),
  };
}

function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function isStringArray(value: unknown): value is readonly string[] {
  return isUnknownArray(value) && value.every((item) => typeof item === "string");
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`cargo metadata ${label} is invalid`);
  return value;
}

function licenseText(license: ComponentLicense | undefined): string {
  if (license === undefined) return "UNKNOWN";
  return "expression" in license ? license.expression : license.license.id;
}

function capture(command: string, arguments_: readonly string[]): Promise<string> {
  return new Promise((resolveRun, rejectRun) => {
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    const child = spawn(command, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => errors.push(chunk));
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun(Buffer.concat(output).toString("utf8"));
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"}): ${Buffer.concat(errors).toString("utf8").slice(-4096)}`));
    });
  });
}
