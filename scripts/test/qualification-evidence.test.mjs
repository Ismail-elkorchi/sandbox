import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { summarize, writeScopeEvidence } from "../qualification-evidence.ts";

const binary = "a".repeat(64);
const requirements = { lifecycle: ["root", "reset"], resources: ["cap"] };
const observation = (checks, configuration = { buildDigest: binary, hardwareDigest: "b".repeat(64) }) => ({
  formatVersion: 1, configuration, checks, facts: { observed: true }, observedUnixMillis: 1,
});

test("partial scopes never become complete and configurations cannot pool evidence", () => {
  const scopes = summarize([observation(["root"]), observation(["reset"], { buildDigest: binary, hardwareDigest: "c".repeat(64) })], requirements, binary);
  assert.equal(scopes.length, 2);
  assert.deepEqual(scopes.map((scope) => scope.missingChecks), [["reset"], ["root"]]);
  assert.throws(() => summarize([observation(["invented-pass"])], requirements, binary), /invalid/u);
  assert.throws(() => summarize([observation(["root"], { buildDigest: "d".repeat(64) })], requirements, binary), /differently built/u);
  assert.throws(() => summarize([{ ...observation(["root"]), observedUnixMillis: Date.now() + 60_000 }], requirements, binary), /invalid/u);
});

test("same-configuration successful checks yield actual retained evidence, not qualification", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "sandsurf-qualification-evidence-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const scopes = summarize([observation(["root"]), observation(["reset"])], requirements, binary);
  assert.deepEqual(scopes[0].missingChecks, []);
  const [candidate] = await writeScopeEvidence(directory, scopes);
  assert.equal(candidate.complete, true);
  const run = JSON.parse(await readFile(candidate.run, "utf8"));
  const bytes = await readFile(candidate.evidence);
  assert.equal(run.evidenceDigest, createHash("sha256").update(bytes).digest("hex"));
  assert.deepEqual(run.passedChecks, ["root", "reset"]);
  assert.equal(Object.hasOwn(run, "acceptedBy"), false);
  assert.equal(Object.hasOwn(run, "qualification"), false);
  await assert.rejects(writeScopeEvidence(directory, scopes), { code: "EEXIST" });
});
