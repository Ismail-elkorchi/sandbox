import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { sha256File } from "../packages/sandsurf/src/file-integrity.ts";
import { readObservations, summarize, writeScopeEvidence } from "./qualification-evidence.ts";

/** Availability is a gate, not evidence of a running or contained VM. */
export function blockers(probe: unknown): string[] {
  if (typeof probe !== "object" || probe === null || !("mechanisms" in probe) ||
      typeof probe.mechanisms !== "object" || probe.mechanisms === null) {
    throw new Error("invalid native containment probe");
  }
  const mechanisms = probe.mechanisms as Record<string, unknown>;
  return ["namespace-launcher", "network-namespace", "native-socket-boundary", "landlock", "seccomp"].flatMap((name) => {
    const value = mechanisms[name];
    if (typeof value !== "object" || value === null || !("state" in value)) return [`${name}: missing observation`];
    if (value.state === "available") return [];
    const detail = "detail" in value && typeof value.detail === "string" ? value.detail.slice(0, 4096) : "no verified availability";
    return [`${name}: ${String(value.state)} (${detail})`];
  });
}

async function run(executable: string, args: string[], timeout: number, env = process.env): Promise<string> {
  return new Promise((resolveRun, rejectRun) => execFile(executable, args, {
    timeout, maxBuffer: 512 * 1024, env,
  }, (error, stdout, stderr) => error === null ? resolveRun(stdout) : rejectRun(new Error(`${executable} failed: ${stderr || error.message}`))));
}

async function main(): Promise<void> {
  if (process.platform !== "linux" || process.arch !== "x64") throw new Error("this installed-computer qualification requires Linux x64");
  const candidate = resolve("packages/sandsurf/native/linux-x64/sandsurf-host-linux-x64");
  const probe: unknown = JSON.parse(await run(candidate, ["--linux-kernel-probe"], 60_000));
  const unavailable = blockers(probe);
  try { await access("/dev/kvm", constants.R_OK | constants.W_OK); }
  catch { unavailable.push("KVM is not readable and writable by the qualification account"); }
  const storage = process.env.SANDSURF_QUALIFICATION_ROOT;
  const fixtures = {
    computer: ["CON", "forked-machine", "derived-machine", "expiring-machine"],
    network: ["native-network-hardware"],
    workloads: ["linux-workloads"],
    systemd: ["independent-machine"],
    "image-report": ["image-report"],
  };
  if (storage === undefined || !isAbsolute(storage)) {
    unavailable.push("operator-provisioned bounded volumes are required: set SANDSURF_QUALIFICATION_ROOT; each fixture needs a 32GiB shared host volume; CON needs a 40GiB machine volume for retained captures and other identities need independent 8GiB machine volumes");
  } else {
    for (const [fixture, identities] of Object.entries(fixtures)) {
      const directory = resolve(storage, fixture);
      for (const id of [undefined, ...identities]) {
        try {
          const args = ["storage-volume", "--directory", directory, ...(id === undefined ? [] : ["--machine", id])];
          const volume = JSON.parse(await run(candidate, args, 10_000));
          const requiredBytes = (id === undefined ? 32 : id === "CON" ? 40 : 8) * 1024 ** 3;
          if (id === undefined ? volume.bytes < requiredBytes : volume.bytes !== requiredBytes) {
            throw new Error(id === undefined ? `shared fixture volume needs at least ${requiredBytes} bytes` : `machine fixture needs a ${requiredBytes}-byte bounded volume`);
          }
        } catch (error) { unavailable.push(`${fixture}${id === undefined ? "" : "/" + id}: ${String(error)}`); }
      }
    }
  }
  const report = { formatVersion: 1, nativeBinaryDigest: await sha256File(candidate, 512 * 1024 ** 2),
    observedUnixMillis: Date.now(), status: unavailable.length === 0 ? "eligible-not-qualified" : "blocked",
    blockers: unavailable, probe, storageFixtures: fixtures };
  const output = process.argv[2];
  if (output === undefined || !isAbsolute(output)) throw new Error("qualification requires an absolute new report path");
  if (output !== undefined) await writeFile(resolve(output), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (unavailable.length !== 0) {
    process.stderr.write("Hardware qualification remains blocked. Host policy is unchanged; source/installed-package checks are independent.\n");
    process.exitCode = 2;
    return;
  }
  const npm = process.env.npm_execpath;
  if (npm === undefined) throw new Error("run through npm run qualify:linux");
  // The actual contract runs against the installed tarball, not a source
  // binary or a probe. An unsuccessful test is never changed to a skip/pass.
  const evidence = `${resolve(output)}.evidence`;
  await mkdir(evidence, { mode: 0o700 });
  const observations = resolve(evidence, "observations");
  await mkdir(observations, { mode: 0o700 });
  let outcome: { readonly kind: "passed" | "failed"; readonly output: string };
  try {
    outcome = { kind: "passed", output: await run(process.execPath, [npm, "run", "test:package"], 30 * 60_000, {
      ...process.env, SANDSURF_KVM_TEST: "1", SANDSURF_KVM_NETWORK_TEST: "1",
      SANDSURF_SERVICE_MANAGER_TEST: "1", SANDSURF_LINUX_QUALIFICATION: "1",
      SANDSURF_QUALIFICATION_EVIDENCE_DIRECTORY: observations,
    }) };
  } catch (error) { outcome = { kind: "failed", output: String(error) }; }
  await writeFile(resolve(evidence, "suite.log"), outcome.output, { flag: "wx", mode: 0o600 });
  const requirements = JSON.parse(await run(candidate, ["qualification-requirements", "--directory", storage!], 10_000)) as Record<string, string[]>;
  const scopes = summarize(await readObservations(observations), requirements, report.nativeBinaryDigest);
  const candidates = await writeScopeEvidence(evidence, scopes);
  const complete = outcome.kind === "passed" && Object.keys(requirements).every((scope) => candidates.some((candidate) => candidate.scope === scope && candidate.complete));
  const result = { formatVersion: 1, nativeBinaryDigest: report.nativeBinaryDigest, prerequisiteReport: resolve(output),
    status: outcome.kind === "failed" ? "failed" : complete ? "tested-unaccepted" : "incomplete",
    suite: outcome.kind, evidenceDirectory: evidence, candidates,
    missingScopes: Object.keys(requirements).filter((scope) => !candidates.some((candidate) => candidate.scope === scope && candidate.complete)) };
  await writeFile(`${resolve(output)}.result.json`, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(outcome.output);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = outcome.kind === "failed" ? 1 : complete ? 0 : 2;
}

if (process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await main();
