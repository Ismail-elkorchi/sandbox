import { writeFile } from "node:fs/promises";
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

await generate("sandbox-supervisor", "@ismail-elkorchi/sandbox", resolve("packages/sandbox"), []);
await generate("sandbox-vm-runtime", "@ismail-elkorchi/sandbox-hardware-vm", resolve("packages/sandbox-hardware-vm"), [
  {
    type: "application",
    name: "firecracker",
    version: "1.16.1",
    licenses: [{ license: { id: "Apache-2.0" } }],
    hashes: [{ alg: "SHA-256", content: "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7" }],
  },
]);

async function generate(rootName: string, npmName: string, destination: string, additional: readonly Component[]): Promise<void> {
  const root = metadata.packages.find((package_) => package_.name === rootName);
  if (root === undefined) throw new Error(`missing cargo package ${rootName}`);
  const identifiers = closure(root.id);
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
    metadata: { component: { type: "application", name: npmName, version: "0.1.0" } },
    components,
  };
  await writeFile(resolve(destination, "SBOM.cdx.json"), `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o644 });
  const notices = components
    .map((component) => `${component.name} ${component.version}\t${licenseText(component.licenses[0])}`)
    .join("\n");
  await writeFile(resolve(destination, "THIRD-PARTY"), `Third-party components\n\n${notices}\n`, { mode: 0o644 });
}

function closure(root: string): Set<string> {
  const visited = new Set<string>();
  const pending = [root];
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
