import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import net from "node:net";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { openSandboxExecutionRepository, SandboxExecutionControlError } from "../dist/index.js";
import { digestRun, executionRecordReadMetrics, finishRetirement, normalizeLimits, readRecord, retireExecution, writeControl, writeRecord } from "../dist/execution-record.js";
import { controlResponse, sendControl } from "../dist/execution-control.js";
import { digest, fixture } from "./fixtures/execution-records.mjs";

async function repositoryTest(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-reliability-"));
  const repository = await openSandboxExecutionRepository({ directory, ...options });
  t.after(async () => { await repository.close(); await rm(directory, { recursive: true, force: true }); });
  return { directory, repository };
}

test("runtime initialization failure publishes an unstarted rejection and releases the control server", { timeout: 5000 }, async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const run = { isolation: { kind: "process" }, process: {}, resources: { output: { enforcement: "hard", scope: "process", value: 1024 } } };
  const item = await fixture(directory, "bootstrap-failure", { requestDigest: digestRun(run), outputLimit: 1024 });
  const child = spawn(process.execPath, [fileURLToPath(new URL("./fixtures/execution-bootstrap-failure.mjs", import.meta.url)), item.directory, item.initial.executionId], {
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let diagnostic = "";
  child.stderr.on("data", (chunk) => { diagnostic += chunk; });
  const exited = once(child, "exit");
  await writeRecord(item.directory, { ...item.initial, workerPid: child.pid });
  child.stdio[3].end(JSON.stringify({ schemaVersion: 1, run, limits: normalizeLimits({ directory }) }));
  const [code] = await exited;
  assert.equal(code, 0, diagnostic);
  const observation = await repository.inspect(item.initial.executionId);
  assert.equal(observation.kind, "rejected");
  assert.equal(observation.error.targetExecuted, false);
  await repository.forget(item.initial.executionId, { receiptDigest: observation.receipt.digest });
});

test("settled and rejected receipts retain exact identity across clock advancement and restart", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  for (const kind of ["settled", "rejected"]) {
    const item = await fixture(directory, kind);
    if (kind === "settled") await item.append("stdout", "original bytes");
    const terminal = await (kind === "settled" ? item.settle() : item.reject());
    t.mock.timers.enable({ apis: ["Date"], now: Date.now() + 365 * 24 * 60 * 60 * 1000 });
    const reopened = await openSandboxExecutionRepository({ directory });
    try {
      const observation = await reopened.inspect(kind, { maxBytes: 100 });
      assert.equal(observation.kind, kind);
      assert.deepEqual(observation.receipt, terminal.receipt);
      assert.equal(observation.output.kind, "available");
      if (kind === "settled") assert.equal(Buffer.concat(observation.output.chunks.map((chunk) => chunk.data)).toString(), "original bytes");
      const concurrent = await Promise.all(Array.from({ length: 8 }, () => repository.inspect(kind)));
      assert.ok(concurrent.every((value) => value.receipt.digest === terminal.receipt.digest));
      await assert.rejects(writeRecord(item.directory, { ...terminal, phase: "unknown", unknownAtMs: 1, diagnostic: "stale worker failure" }), /immutable/);
    } finally { await reopened.close(); t.mock.timers.reset(); }
  }
});

test("output damage does not erase independently verified terminal truth", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const item = await fixture(directory, "damaged-output");
  await item.append("stderr", "secret test bytes");
  const terminal = await item.settle();
  await writeFile(join(item.directory, "output.jsonl"), "{broken}\n");
  assert.equal((await repository.inspect("damaged-output")).output.kind, "not-requested");
  const corrupt = await repository.inspect("damaged-output", { maxBytes: 100 });
  assert.equal(corrupt.kind, "settled");
  assert.deepEqual(corrupt.receipt, terminal.receipt);
  assert.equal(corrupt.output.reason, "corrupt");
  await rm(join(item.directory, "output.jsonl"));
  const missing = await repository.inspect("damaged-output", { maxBytes: 100 });
  assert.equal(missing.kind, "settled");
  assert.equal(missing.output.reason, "missing");
  await repository.forget("damaged-output", { receiptDigest: terminal.receipt.digest });
  assert.equal((await repository.inspect("damaged-output")).kind, "retired");
  assert.equal((await repository.inspect("damaged-output", { maxBytes: 1 })).output.reason, "released");
});

test("release is exact, repeatable, crash recoverable, and never permits replay", async (t) => {
  const limits = { maxRetainedExecutions: 1, maxTotalOutputBytes: 1024, maxRetainedIdentities: 4 };
  const { directory, repository } = await repositoryTest(t, limits);
  const item = await fixture(directory, "release", { outputLimit: 1024, limits });
  await item.append("stdout", "unconsumed");
  const terminal = await item.settle();
  await assert.rejects(repository.forget("release", { receiptDigest: digest("f") }), /does not match/);
  await assert.rejects(fixture(directory, "over-capacity", { outputLimit: 1, limits }), /capacity is exhausted/);
  const retired = retireExecution(directory, "release", terminal.receipt.digest);
  assert.equal((await repository.inspect("release")).cleanupPending, true);
  assert.equal(await readFile(join(item.directory, "output.jsonl"), "utf8").then((text) => text.length > 0), true);
  await assert.rejects(fixture(directory, "still-reserved", { outputLimit: 1, limits }), /capacity is exhausted/);
  // Simulate interruption after deletion and before releasing the reservation.
  await rm(item.directory, { recursive: true });
  await finishRetirement(directory, retired);
  await Promise.all([repository.forget("release", { receiptDigest: terminal.receipt.digest }), repository.forget("release", { receiptDigest: terminal.receipt.digest })]);
  await assert.rejects(repository.forget("release", { receiptDigest: digest("e") }), /conflicts/);
  const next = await fixture(directory, "new-identity", { outputLimit: 1024, limits });
  await next.reject();
  assert.equal((await readRecord(item.directory, "release")).phase, "retired");
});

test("live and unknown effects cannot be forgotten; uncertainty acknowledgement is separate", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const item = await fixture(directory, "uncertain");
  await item.start();
  await assert.rejects(repository.forget("uncertain", { receiptDigest: digest("a") }), /live or uncertain/);
  const observed = await repository.inspect("uncertain");
  assert.equal(observed.kind, "unknown");
  assert.equal(observed.controlFailure, "unreachable");
  await repository.acknowledgeUnknown("uncertain");
  await repository.acknowledgeUnknown("uncertain");
  assert.equal((await repository.inspect("uncertain")).reason, "acknowledged-unknown");
  const live = await fixture(directory, "live");
  await live.start({ workerPid: process.pid });
  await assert.rejects(repository.acknowledgeUnknown("live"), /potentially live/);
});

test("retired identities remain bounded and metadata admission is independent of output capacity", async (t) => {
  const limits = { maxRetainedExecutions: 1, maxRetainedIdentities: 1 };
  const one = await repositoryTest(t, limits);
  const item = await fixture(one.directory, "only-identity", { limits });
  const terminal = await item.reject();
  await one.repository.forget("only-identity", { receiptDigest: terminal.receipt.digest });
  await assert.rejects(fixture(one.directory, "second-identity", { limits }), /identity admission capacity/);
  const metadataLimits = { maxTotalMetadataBytes: 8 * 1024 * 1024 };
  const metadata = await repositoryTest(t, metadataLimits);
  await fixture(metadata.directory, "uses-metadata", { outputLimit: 1, limits: metadataLimits });
  await assert.rejects(fixture(metadata.directory, "metadata-exhausted", { outputLimit: 1, limits: metadataLimits }), /retention admission capacity/);
});

test("inventory pages preserve terminal, live and unknown observations", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const endpoint = await server(t, (socket, request) => socket.end(controlResponse(request.token, request.id)));
  const terminal = await fixture(directory, "terminal"); await terminal.reject();
  const live = await fixture(directory, "running", { endpoint }); await live.start();
  const lost = await fixture(directory, "unknown"); await lost.start();
  const first = await repository.reconcile({ limit: 2 });
  assert.deepEqual(first.observations.map((value) => value.kind), ["rejected", "running"]);
  assert.ok(first.nextCursor);
  const last = await repository.reconcile({ afterCursor: first.nextCursor, limit: 2 });
  assert.deepEqual(last.observations.map((value) => value.kind), ["unknown"]);
  assert.equal(last.nextCursor, undefined);
  assert.ok(first.observations.every((value) => value.output.kind === "not-requested"));
});

test("single-identity status reads one record and no log regardless of inventory size", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  for (let index = 0; index < 50; index++) {
    const item = await fixture(directory, "inventory-" + index); await item.reject();
    await rm(join(item.directory, "output.jsonl"));
  }
  const before = { ...executionRecordReadMetrics };
  const observation = await repository.inspect("inventory-49");
  assert.equal(observation.kind, "rejected"); assert.equal(observation.output.kind, "not-requested");
  assert.equal(executionRecordReadMetrics.records - before.records, 1);
  assert.ok(executionRecordReadMetrics.bytes - before.bytes < 2048);
});

test("terminal publication between state read and failed ping uses the final committed boundary", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  let item;
  const endpoint = await server(t, async (socket) => {
    await item.append("stderr", "final");
    await item.settle();
    socket.destroy();
  });
  item = await fixture(directory, "publication-race", { endpoint });
  await item.append("stdout", "first");
  await item.start();
  const observed = await repository.inspect("publication-race", { maxBytes: 100 });
  assert.equal(observed.kind, "settled");
  assert.equal(observed.receipt.finalCursor, 10);
  assert.equal(Buffer.concat(observed.output.chunks.map((chunk) => chunk.data)).toString(), "firstfinal");
  assert.equal((await readRecord(item.directory, "publication-race")).receipt.digest, observed.receipt.digest);
});

test("a newly committed endpoint is authenticated after a failed startup observation", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const endpoint = await server(t, (socket, request) => socket.end(controlResponse(request.token, request.id)));
  const item = await fixture(directory, "late-endpoint", { endpoint });
  const publication = new Promise((resolve, reject) => setTimeout(() => item.prepare().then(resolve, reject), 1));
  const observation = await repository.inspect("late-endpoint");
  await publication;
  assert.equal(observation.kind, "prepared");
  assert.equal(observation.policyDigest, item.running.policyDigest);
});

test("control transport preserves refused, timed out, authenticated rejection and malformed reply causes", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const refused = await server(t, () => {});
  // A bound endpoint that was closed deterministically refuses the connection.
  await new Promise((resolve) => servers.get(refused).close(resolve));
  const cases = [
    ["unreachable", refused],
    ["timeout", await server(t, () => {})],
    ["authentication-rejected", await server(t, (socket, request) => socket.end(controlResponse(request.token, request.id, "authentication-rejected")))],
    ["malformed-response", await server(t, (socket) => socket.end('{"accepted":true,"error":"DO-NOT-LEAK"}\n'))],
    ["operation-rejected", await server(t, (socket, request) => socket.end(controlResponse(request.token, request.id, "operation-rejected")))],
  ];
  for (const [failure, endpoint] of cases) {
    const item = await fixture(directory, failure, { endpoint });
    await item.start();
    const observation = await repository.inspect(failure);
    assert.equal(observation.kind, "unknown");
    assert.equal(observation.controlFailure, failure);
    assert.ok(!JSON.stringify(observation).includes("DO-NOT-LEAK"));
    if (failure !== "authentication-rejected" && failure !== "malformed-response") assert.ok(!observation.diagnostic.includes("authenticat"));
  }
});

test("lost input replies reconcile applied writes and never blindly resend ambiguous input", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  let writes = 0; let publishApplied = true;
  const endpoint = await server(t, (socket, request) => {
    if (request.kind === "ping") return socket.end(controlResponse(request.token, request.id));
    writes++;
    const { token, ...command } = request;
    writeControl(directory, "input", { id: command.id, digest: digestRun(command), status: publishApplied ? "applied" : "accepted" });
    socket.destroy();
  });
  const item = await fixture(directory, "input", { endpoint }); await item.start();
  await repository.writeInput("input", Buffer.from("one"));
  assert.equal(writes, 1);
  publishApplied = false;
  await assert.rejects(repository.writeInput("input", Buffer.from("two")), (error) => error instanceof SandboxExecutionControlError && error.delivery === "unknown" && error.observation.kind === "running");
  assert.equal(writes, 2);
});

test("ambiguous activation and termination reconcile committed authority without resending", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  let item; let mutations = 0;
  const endpoint = await server(t, async (socket, request) => {
    mutations++;
    if (request.kind === "activate") await item.accept();
    else await item.settle();
    socket.destroy();
  });
  item = await fixture(directory, "activation-delivery", { endpoint }); await item.prepare();
  await repository.activate("activation-delivery", item.running);
  assert.equal((await readRecord(item.directory, "activation-delivery")).phase, "activating");
  assert.equal(mutations, 1);
  await item.start();
  await repository.terminate("activation-delivery");
  assert.equal((await repository.inspect("activation-delivery")).kind, "settled");
  assert.equal(mutations, 2);
});

test("receipt tampering fails integrity without repairing or deleting evidence", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const item = await fixture(directory, "tampered"); await item.settle();
  const db = new DatabaseSync(join(directory, "executions.sqlite"));
  try {
    const envelope = JSON.parse(db.prepare("SELECT state FROM executions WHERE execution_id = ?").get("tampered").state);
    envelope.value.result.termination.code = 9;
    // Recomputing only the storage envelope must not bypass the receipt binding.
    envelope.sha256 = digestRun(envelope.value);
    const serialized = JSON.stringify(envelope);
    db.prepare("UPDATE executions SET state = ? WHERE execution_id = ?").run(serialized, "tampered");
    assert.equal((await repository.inspect("tampered")).reason, "corrupt-record");
    assert.equal(db.prepare("SELECT state FROM executions WHERE execution_id = ?").get("tampered").state, serialized);
  } finally { db.close(); }
});

test("incompatible expired storage and removed options are rejected intact", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-incompatible-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const oldDirectory = join(directory, "execution-old"); await mkdir(oldDirectory);
  const text = '{"schemaVersion":1,"phase":"expired"}';
  await writeFile(join(oldDirectory, "state.json"), text);
  await assert.rejects(openSandboxExecutionRepository({ directory }), /Incompatible/);
  assert.equal(await readFile(join(oldDirectory, "state.json"), "utf8"), text);
  await assert.rejects(openSandboxExecutionRepository({ directory, completedRetentionMs: 10 }), /Unsupported/);
});

test("process death before and after terminal commit preserves one publication authority", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  for (const action of ["uncommitted-publication", "committed-publication"]) {
    const item = await fixture(directory, action); await item.append("stdout", "complete"); await item.start();
    const terminal = item.settledRecord();
    await interrupt({ root: directory, action, record: terminal });
    const reopened = await openSandboxExecutionRepository({ directory });
    try {
      const observation = await reopened.inspect(action, { maxBytes: 1024 });
      assert.equal(observation.kind, action === "uncommitted-publication" ? "unknown" : "settled");
      const state = await readRecord(item.directory, action);
      assert.equal(state.phase, action === "uncommitted-publication" ? "running" : "settled");
      if (observation.kind === "settled") assert.equal(observation.receipt.digest, terminal.receipt.digest);
    } finally { await reopened.close(); }
  }
});

test("a new client completes retirement interrupted before or after output deletion", async (t) => {
  const { directory } = await repositoryTest(t);
  for (const action of ["retired-before-delete", "deleted-output"]) {
    const item = await fixture(directory, action); await item.append("stdout", "receipt bytes");
    const terminal = await item.settle();
    await interrupt({ root: directory, action, record: terminal });
    const reopened = await openSandboxExecutionRepository({ directory });
    try {
      const interrupted = await reopened.inspect(action);
      assert.equal(interrupted.kind, "retired"); assert.equal(interrupted.cleanupPending, true);
      await reopened.forget(action, { receiptDigest: terminal.receipt.digest });
      assert.equal((await reopened.inspect(action)).cleanupPending, false);
      await assert.rejects(readFile(join(item.directory, "output.jsonl")), { code: "ENOENT" });
    } finally { await reopened.close(); }
  }
});

test("concurrent processes cannot overbook output or metadata reservations", async (t) => {
  const options = { maxRetainedExecutions: 10, maxTotalOutputBytes: 1024, maxTotalMetadataBytes: 16 * 1024 * 1024 };
  const { directory, repository } = await repositoryTest(t, options);
  const template = await fixture(directory, "template", { outputLimit: 512, limits: options });
  const terminal = await template.reject(); await repository.forget("template", { receiptDigest: terminal.receipt.digest });
  const results = await Promise.all(Array.from({ length: 8 }, (_, index) => subprocess({
    root: directory, action: "admit", limits: normalizeLimits({ directory, ...options }),
    record: { ...template.initial, executionId: "concurrent-" + index },
  })));
  assert.equal(results.filter((result) => result.admitted).length, 2);
  assert.ok(results.filter((result) => !result.admitted).every((result) => /capacity is exhausted/.test(result.error)));
  assert.equal((await repository.reconcile()).observations.length, 3);
});

test("catalog lock failure is storage unavailability, not failed authentication or corrupt outcome", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const item = await fixture(directory, "locked"); const terminal = await item.reject();
  const db = new DatabaseSync(join(directory, "executions.sqlite"));
  try {
    db.exec("BEGIN EXCLUSIVE");
    const observation = await repository.inspect("locked");
    assert.equal(observation.reason, "storage-unavailable");
    assert.equal(observation.controlFailure, undefined);
    db.exec("ROLLBACK");
    assert.equal((await repository.inspect("locked")).receipt.digest, terminal.receipt.digest);
  } finally { db.close(); }
});

test("lost catalog is unavailable evidence, not an unused execution identity", async (t) => {
  const { directory, repository } = await repositoryTest(t);
  const item = await fixture(directory, "catalog-loss"); await item.reject();
  await rm(join(directory, "executions.sqlite"));
  const observation = await repository.inspect("catalog-loss");
  assert.equal(observation.reason, "storage-unavailable");
  await assert.rejects(openSandboxExecutionRepository({ directory }), /Incompatible/);
});

test("execution identities must survive UTF-8 storage exactly", async (t) => {
  const { repository } = await repositoryTest(t);
  await assert.rejects(repository.inspect("\ud800"), /Execution ID/);
  assert.equal((await repository.inspect("valid-😀")).reason, "not-found");
});

function child(payload) {
  const process = spawn(globalThis.process.execPath, [join(import.meta.dirname, "fixtures/execution-interruption.mjs")], { stdio: ["pipe", "pipe", "pipe"] });
  process.stdin.end(JSON.stringify(payload));
  return process;
}
async function interrupt(payload) {
  const process = child(payload);
  const exited = new Promise((resolve, reject) => { process.once("error", reject); process.once("exit", resolve); });
  let text = "";
  for await (const chunk of process.stdout) {
    text += chunk;
    if (text.includes("ready\n")) { process.kill("SIGKILL"); break; }
  }
  await exited;
  assert.equal(text, "ready\n");
}
async function subprocess(payload) {
  const process = child(payload);
  const exited = new Promise((resolve, reject) => { process.once("error", reject); process.once("exit", resolve); });
  let text = ""; for await (const chunk of process.stdout) text += chunk;
  assert.equal(await exited, 0);
  return JSON.parse(text);
}

const servers = new Map();
async function server(t, handler) {
  const sockets = new Set();
  const instance = net.createServer((socket) => {
    sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.on("error", () => {});
    let text = "";
    socket.on("data", (chunk) => {
      text += chunk;
      if (text.includes("\n")) { socket.removeAllListeners("data"); Promise.resolve(handler(socket, JSON.parse(text))).catch((error) => socket.destroy(error)); }
    });
  });
  await new Promise((resolve, reject) => { instance.once("error", reject); instance.listen(0, "127.0.0.1", resolve); });
  const port = instance.address().port; servers.set(port, instance);
  t.after(async () => { for (const socket of sockets) socket.destroy(); if (instance.listening) await new Promise((resolve) => instance.close(resolve)); servers.delete(port); });
  return port;
}
