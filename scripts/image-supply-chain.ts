import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Component } from "./native-supply-chain.ts";

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
async function document(path: string): Promise<{ bytes: Buffer; value: unknown }> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0 || metadata.size > 1024 * 1024) {
    throw new Error("OS supply-chain input is not a bounded regular document");
  }
  const bytes = await readFile(path);
  if (bytes.length !== metadata.size) throw new Error("OS supply-chain document changed length");
  return { bytes, value: JSON.parse(bytes.toString("utf8")) };
}

/** Inventory the actually assembled, digest-bound default OS seeds. Build
 * commit URLs are explicitly pointers; they do not substitute for source bytes.
 * Package and source-archive distribution have different obligations. */
export async function imageComponents(root: string): Promise<Component[]> {
  const index = (await document(resolve(root, "manifest.json"))).value;
  if (!record(index) || index.formatVersion !== 1 || !record(index.files) || Object.keys(index.files).length === 0 || Object.keys(index.files).length > 2) {
    throw new Error("invalid default OS image inventory");
  }
  const components = new Map<string, { component: Component; images: Set<string> }>();
  for (const [relative, expected] of Object.entries(index.files)) {
    const match = /^development-(x64|arm64)\/manifest\.json$/u.exec(relative);
    if (match === null || typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) {
      throw new Error("invalid default OS image identity");
    }
    const { bytes, value: manifest } = await document(resolve(root, relative));
    if (createHash("sha256").update(bytes).digest("hex") !== expected || !record(manifest) ||
        manifest.formatVersion !== 1 || manifest.architecture !== match[1] || !record(manifest.system) ||
        !record(manifest.system.provenance) || manifest.system.provenance.kind !== "assembled") {
      throw new Error("default OS image provenance differs from the packaged identity");
    }
    const inventory = manifest.system.provenance.distribution;
    if (!record(inventory) || inventory.kind !== "alpine" || typeof inventory.databaseDigest !== "string" ||
        !/^[a-f0-9]{64}$/u.test(inventory.databaseDigest) || !Array.isArray(inventory.packages) ||
        inventory.packages.length === 0 || inventory.packages.length > 512) {
      throw new Error("default OS lacks its final installed-package inventory");
    }
    if (!record(manifest.system.provenance.materials) ||
        manifest.system.provenance.materials["alpine-installed-database"] !== inventory.databaseDigest) {
      throw new Error("default OS package inventory differs from the assembled input materials");
    }
    let previous = "";
    for (const item of inventory.packages as unknown[]) {
      if (!record(item) || Object.keys(item).sort().join(",") !== "architecture,buildCommit,license,name,origin,packageChecksum,version" ||
          typeof item.name !== "string" || !/^[a-z0-9][a-z0-9+_.-]{0,127}$/u.test(item.name) || item.name <= previous ||
          typeof item.origin !== "string" || !/^[a-z0-9][a-z0-9+_.-]{0,127}$/u.test(item.origin) ||
          typeof item.version !== "string" || !/^[0-9][A-Za-z0-9+_.:~\-]{0,127}$/u.test(item.version) ||
          typeof item.architecture !== "string" || !["noarch", match[1] === "x64" ? "x86_64" : "aarch64"].includes(item.architecture) ||
          typeof item.license !== "string" || item.license.length === 0 || item.license.length > 1024 || /[\u0000-\u001f\u007f]/u.test(item.license) ||
          typeof item.buildCommit !== "string" || !/^[a-f0-9]{40}$/u.test(item.buildCommit) ||
          typeof item.packageChecksum !== "string" || !/^Q1[A-Za-z0-9+/=]{28}$/u.test(item.packageChecksum)) {
        throw new Error("malformed final OS package provenance");
      }
      previous = item.name;
      const identity = JSON.stringify(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
      let entry = components.get(identity);
      if (entry === undefined) {
        entry = { component: {
          type: "library", name: `alpine/${item.name} (${item.architecture})`, version: item.version,
          purl: `pkg:apk/alpine/${encodeURIComponent(item.name)}@${encodeURIComponent(item.version)}?arch=${item.architecture}`,
          licenses: [{ license: { name: item.license } }],
          properties: [
            { name: "sandsurf:distribution-origin", value: item.origin },
            { name: "sandsurf:distribution-build-commit", value: item.buildCommit },
            { name: "sandsurf:source-pointer", value: `https://gitlab.alpinelinux.org/alpine/aports/-/commit/${item.buildCommit}` },
            { name: "sandsurf:apk-installed-record-checksum", value: item.packageChecksum },
          ],
        }, images: new Set() };
        components.set(identity, entry);
      }
      entry.images.add(expected);
    }
  }
  return [...components.values()].map(({ component, images }) => ({ ...component,
    properties: [...component.properties!, ...[...images].sort().map((value) => ({ name: "sandsurf:machine-image", value }))],
  }));
}
