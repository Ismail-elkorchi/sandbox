import { createHash } from "node:crypto";
import { lstat, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { NativeQualificationConfiguration } from "../packages/sandsurf/src/contracts.ts";

export interface CheckObservation {
  readonly formatVersion: 1;
  readonly configuration: NativeQualificationConfiguration;
  readonly observedUnixMillis: number;
  readonly checks: readonly string[];
  readonly facts: unknown;
}
export interface ScopeEvidence {
  readonly configuration: NativeQualificationConfiguration;
  readonly scope: string;
  readonly passedChecks: readonly string[];
  readonly missingChecks: readonly string[];
  readonly observedUnixMillis: number;
  readonly observations: readonly CheckObservation[];
}

function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return item;
    return Object.fromEntries(Object.entries(item).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
  });
}
export function summarize(observations: readonly CheckObservation[], requirements: Readonly<Record<string, readonly string[]>>, binary: string): ScopeEvidence[] {
  const known = new Set(Object.values(requirements).flat());
  const configurations = new Map<string, CheckObservation[]>();
  for (const item of observations) {
    if (item.formatVersion !== 1 || item.configuration?.buildDigest !== binary ||
      !Number.isSafeInteger(item.observedUnixMillis) || item.observedUnixMillis <= 0 || item.observedUnixMillis > Date.now() ||
      !Array.isArray(item.checks) || item.checks.length === 0 || item.checks.length > 64 || item.checks.some((name) => !known.has(name))) {
      throw new Error("invalid or differently built hardware check observation");
    }
    const identity = canonical(item.configuration);
    const group = configurations.get(identity) ?? [];
    group.push(item); configurations.set(identity, group);
  }
  const result: ScopeEvidence[] = [];
  for (const group of configurations.values()) {
    const checks = new Set(group.flatMap((item) => item.checks));
    for (const [scope, required] of Object.entries(requirements)) {
      const passedChecks = required.filter((name) => checks.has(name));
      if (passedChecks.length === 0) continue;
      result.push({ configuration: group[0]!.configuration, scope, passedChecks,
        missingChecks: required.filter((name) => !checks.has(name)),
        observedUnixMillis: Math.max(...group.map((item) => item.observedUnixMillis)),
        observations: group.filter((item) => item.checks.some((check) => required.includes(check))) });
    }
  }
  return result;
}

export async function readObservations(directory: string): Promise<CheckObservation[]> {
  const names = await readdir(directory);
  if (names.length > 256) throw new Error("hardware observation inventory exceeds bound");
  const observations: CheckObservation[] = [];
  for (const name of names) {
    if (!/^check-[a-f0-9]{64}\.json$/u.test(name)) throw new Error("unexpected hardware observation file");
    const path = join(directory, name);
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0 || metadata.size > 128 * 1024) throw new Error("hardware observation is not a private bounded file");
    const bytes = await readFile(path);
    if (createHash("sha256").update(bytes).digest("hex") !== name.slice(6, -5)) throw new Error("hardware observation identity changed");
    observations.push(JSON.parse(bytes.toString()) as CheckObservation);
  }
  return observations;
}

/** Materialize actual evidence bytes and candidate runs. Acceptance is a
 * separate explicit operator action; neither tests nor this writer qualify. */
export async function writeScopeEvidence(directory: string, scopes: readonly ScopeEvidence[]): Promise<readonly { readonly scope: string; readonly complete: boolean; readonly run: string; readonly evidence: string }[]> {
  const files = [];
  for (const scope of scopes) {
    const bytes = Buffer.from(`${canonical(scope)}\n`);
    if (bytes.byteLength > 8 * 1024 ** 2) throw new Error("scoped qualification evidence exceeds native bound");
    const evidenceDigest = createHash("sha256").update(bytes).digest("hex");
    const evidence = join(directory, `${scope.scope}-${evidenceDigest}.evidence.json`);
    const run = join(directory, `${scope.scope}-${evidenceDigest}.run.json`);
    await writeFile(evidence, bytes, { flag: "wx", mode: 0o600 });
    await writeFile(run, `${JSON.stringify({ configuration: scope.configuration, scope: scope.scope,
      observedUnixMillis: scope.observedUnixMillis, passedChecks: scope.passedChecks, evidenceDigest }, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    files.push({ scope: scope.scope, complete: scope.missingChecks.length === 0, run, evidence });
  }
  return files;
}
