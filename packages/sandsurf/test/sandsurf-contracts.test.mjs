import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { before, test } from "node:test";
import { Artifact, Machine, Execution, ExecutionInterruptedError, Operation, Sandsurf, SandsurfHostError } from "../dist/index.js";
import { createSandsurfGuestPath, createSandsurfGuestCommand, encodeSandsurfFrame, SandsurfFrameDecoder, sandsurfDigest, sandsurfGuestRequestMetadata, sandsurfGuestPathUtf8, validateSandsurfGuestPath, validateSandsurfGuestCommand, validateSandsurfRelease } from "../dist/sandsurf-protocol.js";
import { parseExecutionInspection, parseExecutionOutcome, parseExecutionReceipt } from "../dist/execution.js";
import { validateProtocol } from "../dist/protocol-validation.js";

function executionRequest(id = "command", stdio = "pipes") {
  return { machineId: "box", generation: 1, executionId: id, operationId: "spawn-command", argv: ["/bin/sh"], cwd: "/workspace",
    environment: {}, user: "agent", stdio, terminalSize: stdio === "terminal" ? { columns: 80, rows: 24, pixelWidth: 0, pixelHeight: 0 } : null,
    activeDeadlineMillis: null, elapsedDeadlineUnixMillis: null, outputBytes: 1024 };
}

test("machine storage identities are explicit and obsolete resource fields are rejected", async () => {
  const host = new Sandsurf({ request: async () => assert.fail("invalid machine request reached transport") }, () => assert.fail("invalid machine request reached authorization"));
  const resources = fixtureView().runtimeConfiguration.resources;
  await assert.rejects(host.machines.create({ image: "a".repeat(64), resources }), /identity is malformed/u);
  await assert.rejects(host.machines.create({ id: "box", image: "a".repeat(64), resources: { ...resources, imageBytes: 1024 } }), /unknown host resource field/u);
  const view = fixtureView();
  view.runtimeConfiguration.resources.imageBytes = 1024;
  const malformed = new Sandsurf({ request: async () => ({ kind: "machine", value: view }) }, () => true);
  await assert.rejects(malformed.machines.connect("box"), (error) => error.category === "protocol");
});
function completedState() {
  return { kind: "exited", outcome: { kind: "exit", code: 0 }, accountingDigest: "c".repeat(64), cleanupDigest: "d".repeat(64),
    output: { finalCursor: 0, chunks: 0, stdoutBytes: 0, stderrBytes: 0, terminalBytes: 0, omittedBytes: 0, finalHash: "a".repeat(64) } };
}
function executionReceipt(request = executionRequest()) {
  const { kind: _kind, ...completion } = completedState();
  const receipt = { machineId: request.machineId, generation: request.generation, executionId: request.executionId, operationId: request.operationId,
    requestDigest: "e".repeat(64), ...completion };
  return { receipt, digest: sandsurfDigest("receipt", receipt) };
}

test("operation handles retain references and separate host intent from guardian delivery", async () => {
  let applied = false;
  const requests = [];
  const host = new Sandsurf({ request: async (request) => {
    requests.push(request);
    assert.equal(request.kind, "get-host-operation");
    return { kind: "host-operation", value: { kind: "secret-put", value: { operationId: request.operationId, requestDigest: "a".repeat(64),
      secret: { id: "secret", version: "opaque-version", bytes: 3 }, applied } } };
  } }, () => assert.fail("operation observation requested authority"));
  const operation = await host.operations.get("put-secret");
  assert.ok(operation instanceof Operation);
  assert.equal(operation.id, "put-secret");
  assert.equal(operation.observation.owner, "host-authority");
  assert.equal(operation.observation.observation.applied, false);
  applied = true;
  assert.equal(operation.observation.observation.applied, false, "cached observation cannot invent external progress");
  assert.equal((await operation.inspect()).observation.applied, true);
  assert.equal(requests.length, 2);

  const command = createSandsurfGuestCommand({ machineId: "box", generation: 1, operationId: "spawn-command", request: { kind: "spawn", request: executionRequest() } });
  const guardian = new Sandsurf({ request: async (request) => {
    assert.equal(request.kind, "get-operation");
    assert.equal(request.machineId, "box");
    return { kind: "runtime", response: { kind: "operation", operation: { kind: "guest", operation: {
      admission: { request: command, binary: null }, delivery: "unknown", evidenceDigest: null,
    } } } };
  } }, () => assert.fail("operation observation requested authority"));
  const delivery = await guardian.operations.get("spawn-command", { machineId: "box" });
  assert.deepEqual(delivery.observation, { operationId: "spawn-command", machineId: "box", owner: "guardian-journal", requestDigest: command.requestDigest,
    observation: { kind: "guest", generation: 1, requestKind: "spawn", delivery: "unknown", evidenceDigest: null } });
});

test("operation lookup rejects mismatched identities, malformed claims and cross-owner records", async () => {
  const base = { kind: "secret-put", value: { operationId: "op", requestDigest: "a".repeat(64), secret: { id: "secret", version: "opaque", bytes: 3 }, applied: false } };
  for (const value of [
    { ...base, value: { ...base.value, operationId: "other" } },
    { ...base, value: { ...base.value, applied: "true" } },
    { ...base, value: { ...base.value, requestDigest: "invalid" } },
    { kind: "guest", value: {} }, { kind: "arbitrary", value: base.value },
  ]) {
    const host = new Sandsurf({ request: async () => ({ kind: "host-operation", value }) }, () => true);
    await assert.rejects(host.operations.get("op"), SandsurfHostError);
  }
  const host = new Sandsurf({ request: async () => ({ kind: "host-operation", value: base }) }, () => true);
  await assert.rejects(host.operations.get("op", { machineId: "box" }), SandsurfHostError);
  const missing = new Sandsurf({ request: async () => ({ kind: "host-operation", value: null }) }, () => true);
  assert.equal(await missing.operations.get("missing"), undefined);
});

test("typed operation observations cover each host record without inventing effect completion", async () => {
  const common = { operationId: "op", machineId: "box", requestDigest: "a".repeat(64) };
  const secret = { id: "secret", version: "opaque", bytes: 3 };
  const resources = fixtureView().runtimeConfiguration.resources;
  const snapshot = { request: { id: "snapshot", operationId: "op", machineId: "box", expectedGeneration: 1, expectedRevision: 1, kind: "disk", parent: null },
    requestDigest: common.requestDigest, phase: "ready", imageDigest: "b".repeat(64), resources, consistency: "crash", systemDiskDigest: "c".repeat(64),
    systemDiskBytes: resources.diskBytes, manifestDigest: "d".repeat(64), sensitive: false, full: null };
  const records = [
    ["lifecycle", { ...common, desired: "running", revision: 1, completion: null }],
    ["configuration", { ...common, revision: 1, configuration: fixtureView().runtimeConfiguration }],
    ["transfer", { ...common, applied: false, approvalId: "approval" }],
    ["image-import", { operationId: "op", requestDigest: common.requestDigest, phase: "admitted", image: null }],
    ["image-release", { operationId: "op", requestDigest: common.requestDigest, imageDigest: "b".repeat(64), cleanupPending: true }],
    ["secret-delivery", { ...common, delivery: { secret }, disclosure: "possible", revocationOperation: null, revoked: false }],
    ["secret-put", { operationId: "op", requestDigest: common.requestDigest, secret, applied: false }],
    ["secret-revocation", { ...common, secret, deliveries: [], terminateRecipients: false, guestCleanupReport: null }],
    ["snapshot", snapshot],
    ["rollback", { ...common, snapshotId: "snapshot", expectedRevision: 1, phase: "admitted", evidenceDigest: null }],
  ];
  for (const [kind, value] of records) {
    const host = new Sandsurf({ request: async () => ({ kind: "host-operation", value: { kind, value } }) }, () => assert.fail("read requested authority"));
    const inspection = (await host.operations.get("op")).observation;
    assert.equal(inspection.operationId, "op");
    assert.equal(inspection.observation.kind, kind);
    assert.equal(inspection.owner, "host-authority");
    assert.equal(inspection.machineId, ["image-import", "image-release", "secret-put"].includes(kind) ? null : "box");
    if (kind === "lifecycle") assert.equal(inspection.observation.intent.completion, null, "intent admission is not observed machine state");
    if (kind === "configuration") assert.equal("delivery" in inspection.observation, false, "configuration admission is not installation evidence");
    if (kind === "secret-delivery") assert.equal(inspection.observation.disclosure, "possible");
  }
});

test("guardian operation views preserve acknowledgement and actual retention as distinct facts", async () => {
  const segment = { id: "segment", machineId: "box", executionId: "command", generation: 1, output: completedState().output };
  const records = [
    { kind: "receipt-acknowledgement", operationId: "op", executionId: "command", receiptDigest: "a".repeat(64) },
    { kind: "output-seal", operationId: "op", requestDigest: "a".repeat(64), segment },
    { kind: "evidence-release", executionId: "command", request: { operationId: "op" }, status: { requestDigest: "a".repeat(64), cleanupPending: true } },
  ];
  for (const record of records) {
    const host = new Sandsurf({ request: async () => ({ kind: "runtime", response: { kind: "operation", operation: record } }) }, () => true);
    const inspection = (await host.operations.get("op", { machineId: "box" })).observation;
    assert.equal(inspection.owner, "guardian-journal");
    assert.equal(inspection.observation.kind, record.kind);
    assert.equal("accepted" in inspection.observation, false);
    if (record.kind === "evidence-release") assert.equal(inspection.observation.status.cleanupPending, true);
  }
});

test("execution reports expose one validated request, state and lineage model", () => {
  const request = executionRequest();
  const value = { request, guestPid: 23, state: completedState(), lineage: null };
  assert.deepEqual(parseExecutionInspection(value), value);
  for (const state of [
    { kind: "running", outcome: { kind: "exit", code: 0 } },
    { kind: "draining", outcome: { kind: "exit", code: 0 } },
    { ...completedState(), output: { ...completedState().output, chunks: 1 } },
    { ...completedState(), outcome: { kind: "exit", code: 0.5 } },
    { kind: "unknown", evidence: "not-a-digest" },
    { kind: "healthy" },
  ]) assert.throws(() => parseExecutionInspection({ ...value, state }), SandsurfHostError);
  for (const invalid of [
    { ...value, guestPid: 0x1_0000_0000 }, { ...value, lineage: undefined },
    { ...value, request: { ...request, generation: 0 } },
    { ...value, request: { ...request, hostAuthority: "guest-owned" } },
    { ...value, lineage: { sourceMachineId: "box", sourceGeneration: 1, snapshotId: "snapshot" } },
  ]) assert.throws(() => parseExecutionInspection(invalid), SandsurfHostError);
  const restored = { ...value, request: { ...request, executionId: "restored-command", generation: 2 }, lineage: {
    logicalExecutionId: "command", sourceExecutionId: "command", sourceMachineId: "box",
    sourceGeneration: 1, snapshotId: "snapshot", outputAnchor: completedState().output,
  } };
  assert.deepEqual(parseExecutionInspection(restored).lineage, restored.lineage);
  const parsed = parseExecutionInspection(value);
  request.environment.UNRELATED = "changed-after-parse";
  assert.equal(parsed.request.environment.UNRELATED, undefined);
});

test("execution outcomes are closed unions and receipts retain their exact hash-bound bytes", () => {
  for (const outcome of [{ kind: "exit", code: -1 }, { kind: "signal", signal: 9 }, { kind: "deadline-exceeded" },
    { kind: "spawn-failed", reason: "a".repeat(64) }, { kind: "interrupted", evidence: "a".repeat(64) }]) {
    assert.deepEqual(parseExecutionOutcome(outcome), outcome);
  }
  for (const outcome of [{ kind: "exit", code: 2147483648 }, { kind: "signal", signal: 0 },
    { kind: "deadline-exceeded", code: 0 }, { kind: "spawn-failed", reason: "invalid" }]) assert.throws(() => parseExecutionOutcome(outcome), SandsurfHostError);
  const { receipt, digest } = executionReceipt();
  assert.deepEqual(parseExecutionReceipt(receipt, digest), receipt);
  assert.throws(() => parseExecutionReceipt({ ...receipt, outcome: { kind: "exit", code: 1 } }, digest), SandsurfHostError);
  assert.throws(() => parseExecutionReceipt(receipt, "0".repeat(64)), SandsurfHostError);
});

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixture = resolve(root, `target/debug/examples/contract_fixture${process.platform === "win32" ? ".exe" : ""}`);
before(() => {
  const built = spawnSync("cargo", ["build", "--locked", "-p", "sandsurf-protocol", "--example", "contract_fixture"], { cwd: root, encoding: "utf8", timeout: 120_000 });
  assert.equal(built.status, 0, built.stderr);
});
function native(mode, input, ...args) { return spawnSync(fixture, [mode, ...args], { input, maxBuffer: 1024 * 1024, timeout: 10_000 }); }

test("source-generated wire shapes match Rust serde, including generics and flattened variants", () => {
  const emptyObservation = { kind: "unavailable", lastKnown: null };
  const fixtures = [
    ["ExecutionState", completedState()],
    ["ExecutionState", { kind: "draining", outcome: { kind: "exit", code: 0 }, accountingDigest: "a".repeat(64) }],
    ["GuardianInspection", { machineId: "box", observation: emptyObservation, management: emptyObservation, operation: null, lifecycleOperation: null, configurationOperation: null }],
    ["GuestServiceRequest", { kind: "rebind-generation", snapshotId: "snapshot", captureOperationId: "capture", machineId: "box", previousGeneration: 1, generation: 2, bootIdentity: "a".repeat(64), capability: Array(32).fill(255), generationSeed: Array(32).fill(0) }],
    ["FilesystemRequest", { kind: "stat", path: [...Buffer.from("/home/agent")], follow: true }],
    ["RuntimeResponse", { kind: "console-input", accepted: 65536 }],
    ["Resources", fixtureView().runtimeConfiguration.resources],
  ];
  for (const [name, value] of fixtures) {
    const result = native("wire", JSON.stringify(value), name);
    assert.equal(result.status, 0, result.stderr.toString());
    const serialized = JSON.parse(result.stdout);
    assert.deepEqual(serialized, value);
    validateProtocol(name, serialized);
    const invalid = { ...value, anotherAuthority: true };
    assert.throws(() => validateProtocol(name, invalid));
    assert.notEqual(native("wire", JSON.stringify(invalid), name).status, 0);
  }
  const request = fixtures.find(([name]) => name === "GuestServiceRequest")[1];
  for (const capability of [Array(31).fill(0), Array(33).fill(0), Array(32).fill(256), Array(32)]) {
    assert.throws(() => validateProtocol("GuestServiceRequest", { ...request, capability }));
  }
  assert.throws(() => validateProtocol("FilesystemRequest", { kind: "stat", path: [47, -0], follow: true }));
  assert.throws(() => validateProtocol("RuntimeResponse", { kind: "console-input", accepted: 0x1_0000_0000 }));
  assert.throws(() => validateProtocol("GuestServiceRequest", { kind: "processes", extra: true }));
});

test("Rust and TypeScript encode every Sandsurf digest domain identically", () => {
  const value = { z: 1, a: [true, null, "é", -13, Number.MAX_SAFE_INTEGER], "\u{10000}": "astral", "\ue000": "BMP" };
  for (const domain of ["machine", "authority", "operation", "receipt", "output", "release", "image", "snapshot", "transfer", "network", "secret", "resource", "exposure"]) {
    const result = native("digest", JSON.stringify(value), domain);
    assert.equal(result.status, 0, result.stderr.toString());
    assert.equal(result.stdout.toString(), sandsurfDigest(domain, value));
  }
  for (const value of [0.1, -0, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, undefined, "\ud800", new Date()]) assert.throws(() => sandsurfDigest("operation", value));
});

test("Rust and TypeScript agree on valid and invalid command fields", () => {
  const value = createSandsurfGuestCommand({
    machineId: "box", generation: 1, operationId: "op",
    request: { kind: "spawn", request: {
      machineId: "box", generation: 1, executionId: "process", operationId: "op",
      argv: ["/bin/echo", "hello"], cwd: "/workspace", environment: { PATH: "/usr/bin:/bin" },
      user: "agent", stdio: "pipes", terminalSize: null, activeDeadlineMillis: null, elapsedDeadlineUnixMillis: null, outputBytes: 1024,
    } },
  });
  validateSandsurfGuestCommand(value);
  const accepted = native("command", JSON.stringify(value));
  assert.equal(accepted.status, 0, accepted.stderr.toString());
  assert.deepEqual(JSON.parse(accepted.stdout), value);
  for (const invalid of [{ ...value, generation: -1 }, { ...value, generation: 0.5 }, { ...value, machineId: "../escape" }, { ...value, generation: Number.MAX_SAFE_INTEGER + 1 }, { ...value, currentGrants: [] }, { ...value, requestDigest: "a".repeat(64) }, { ...value, request: { ...value.request, request: { ...value.request.request, cwd: "relative" } } }]) {
    assert.throws(() => validateSandsurfGuestCommand(invalid));
    assert.notEqual(native("command", JSON.stringify(invalid)).status, 0);
  }
});

test("release dispositions require a full boundary and explicit evidence fields", () => {
  const output = { finalCursor: 0, chunks: 0, stdoutBytes: 0, stderrBytes: 0, terminalBytes: 0, omittedBytes: 0, finalHash: "a".repeat(64) };
  const receiptDigest = "b".repeat(64);
  for (const disposition of [
    { kind: "complete-capture", commitment: { storeId: "store", commitmentId: "capture", manifestDigest: "c".repeat(64), receiptDigest, output } },
    { kind: "continuing-retention", segment: "segment" },
    { kind: "authorized-loss", authorization: "approval" },
  ]) {
    const value = { operationId: "release", receiptDigest, output, disposition };
    validateSandsurfRelease(value);
    const accepted = native("release", JSON.stringify(value));
    assert.equal(accepted.status, 0, accepted.stderr.toString());
    assert.deepEqual(JSON.parse(accepted.stdout), value);
  }
  for (const value of [{ receiptDigest }, { operationId: "release", receiptDigest, output, disposition: { kind: "acknowledged" } }, { operationId: "release", receiptDigest, output, disposition: { kind: "complete-capture", reference: "some-url" } }]) {
    assert.throws(() => validateSandsurfRelease(value));
    assert.notEqual(native("release", JSON.stringify(value)).status, 0);
  }
});

test("dense binary commands have identical bounded durable admissions in Rust and TypeScript", () => {
  for (const request of [
    { kind: "write-input", executionId: "execution", terminalLeaseId: null, bytes: Array(65536).fill(255) },
    { kind: "filesystem", request: { kind: "write", path: [...Buffer.from("/data")], bytes: Array(65536).fill(255), mode: 0o644, expected: { kind: "any" } } },
  ]) {
    const command = createSandsurfGuestCommand({ machineId: "box", generation: 1, operationId: "dense", request });
    const metadata = sandsurfGuestRequestMetadata(command.request);
    const admission = { request: { ...command, request: metadata.request }, binary: metadata.binary };
    assert.ok(JSON.stringify(admission).length < 2048);
    const accepted = native("admission", JSON.stringify(admission));
    assert.equal(accepted.status, 0, accepted.stderr.toString());
    assert.deepEqual(JSON.parse(accepted.stdout), admission);
    const corrupted = structuredClone(admission);
    corrupted.binary[0].digest = "a".repeat(64);
    assert.notEqual(native("admission", JSON.stringify(corrupted)).status, 0);
  }
});

test("guest paths preserve bytes across Rust and TypeScript", () => {
  const path = createSandsurfGuestPath(Buffer.from([0x2f, 0x77, 0x2f, 0xff]));
  validateSandsurfGuestPath(path);
  assert.equal(sandsurfGuestPathUtf8(path), undefined);
  const accepted = native("path", JSON.stringify(path));
  assert.equal(accepted.status, 0, accepted.stderr.toString());
  assert.deepEqual(JSON.parse(accepted.stdout), path);
  for (const invalid of [[], [...Buffer.from("relative")], [0x2f, 0]]) {
    assert.throws(() => validateSandsurfGuestPath(invalid));
    assert.notEqual(native("path", JSON.stringify(invalid)).status, 0);
  }
});

test("binary frame interoperability includes fragmentary input, EOF and zero-length end", () => {
  for (const kind of ["data", "control", "credit", "end"]) {
    const frame = { kind, stream: kind === "control" ? 0 : 23, sequence: Number.MAX_SAFE_INTEGER, authentication: Buffer.alloc(32), payload: kind === "end" ? Buffer.alloc(0) : kind === "credit" ? Buffer.alloc(8) : Buffer.from([0, 255, 128, 10]) };
    const bytes = encodeSandsurfFrame(frame);
    const nativeResult = native("frame", bytes);
    assert.equal(nativeResult.status, 0, nativeResult.stderr.toString());
    assert.deepEqual(nativeResult.stdout, bytes);
    const decoder = new SandsurfFrameDecoder();
    const decoded = [];
    for (const byte of bytes) decoded.push(...decoder.push(Buffer.from([byte])));
    decoder.finish();
    assert.deepEqual(decoded, [frame]);
    for (let length = 1; length < bytes.length; length++) {
      const partial = new SandsurfFrameDecoder(); [...partial.push(bytes.subarray(0, length))];
      assert.throws(() => partial.finish());
    }
  }
});

test("decoder rejects oversized allocation and remains failed", () => {
  const bytes = encodeSandsurfFrame({ kind: "control", stream: 0, sequence: 1, authentication: Buffer.alloc(32), payload: Buffer.alloc(0) });
  bytes.writeUInt32BE(0xffff_ffff, 20);
  const decoder = new SandsurfFrameDecoder();
  assert.throws(() => [...decoder.push(bytes)]);
  assert.throws(() => decoder.finish());
  assert.throws(() => [...decoder.push(Buffer.alloc(0))]);
  assert.notEqual(native("frame", bytes).status, 0);
});

test("retained artifacts publish without a live machine, revision or redundant uploads", async () => {
  const requests = [];
  const approvals = [];
  const host = new Sandsurf({ request: async (request) => {
    requests.push(request);
    assert.equal(request.kind, "apply-artifact-to-host");
    return { kind: "host-apply", report: { operationId: request.operationId, changeSetDigest: request.changeSet.digest, applied: 0, recovered: false } };
  } }, async (change) => { approvals.push(change); return { approvalId: "publish-approval" }; });
  const manifest = { digest: createHash("sha256").update("SANDSURF-TREE-MANIFEST-V1\0").digest("hex"), entries: [] };
  const artifact = new Artifact(host, { id: "retained", machineId: "destroyed-machine", manifestDigest: manifest.digest, requestDigest: "a".repeat(64), entries: 0, bytes: 0, consistency: "live" }, manifest);
  const destination = resolve("retained-publication");
  await artifact.applyToHost({ destination, operationId: "publish" });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].artifactId, "retained");
  assert.equal(requests[0].machineId, "destroyed-machine");
  assert.equal("expectedRevision" in requests[0], false);
  assert.equal(approvals[0].request.artifactId, "retained");
  assert.equal(approvals[0].request.manifestDigest, manifest.digest);
  assert.equal(approvals[0].request.changeSetDigest, requests[0].changeSet.digest);
});

function fixtureMachine(request, generation = 1, authorizer = async () => { throw new Error("ordinary guest access requested host approval"); }, eventPages, consolePages) {
  const host = new Sandsurf({ request, eventPages, consolePages }, authorizer);
  return new Machine(host, fixtureView(generation));
}

test("native console follows bounded credited pages without polling and drains closed history", async () => {
  let subscriptions = 0;
  const machine = fixtureMachine(async (request) => {
    assert.equal(request.kind, "read-console");
    return { kind: "runtime", response: { kind: "console", page: {
      generation: 1, after: 0, cursor: 0, available: 0, bytes: new Uint8Array(), loss: null, open: true, captureFailed: false,
    } } };
  }, 1, undefined, undefined, async function* (id, generation, after, maximum, signal) {
    assert.equal(id, "box"); assert.equal(generation, 1); assert.equal(after, 0); assert.equal(maximum, 2);
    assert.equal(signal.aborted, false); subscriptions++;
    for (const [cursor, bytes] of [[2, [1, 2]], [4, [3, 4]]]) yield {
      kind: "runtime", response: { kind: "console", page: { generation, after: cursor - 2, cursor, available: 4,
        bytes: Uint8Array.from(bytes), loss: null, open: false, captureFailed: false } },
    };
  });
  const console = await machine.console.attach({ generation: 1 });
  const pages = [];
  for await (const page of console.follow({ maximum: 2 })) pages.push(...page.bytes);
  assert.deepEqual(pages, [1, 2, 3, 4]);
  assert.equal(subscriptions, 1);
});

test("console detach cancels an idle stream and external abort retains its reason", async () => {
  const machine = fixtureMachine(async () => ({ kind: "runtime", response: { kind: "console", page: {
    generation: 1, after: 0, cursor: 0, available: 0, bytes: new Uint8Array(), loss: null, open: true, captureFailed: false,
  } } }), 1, undefined, undefined, async function* (_id, _generation, _after, _maximum, signal) {
    await new Promise((_, reject) => {
      if (signal.aborted) reject(signal.reason);
      else signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
  });
  const console = await machine.console.attach({ generation: 1 });
  const stream = console.follow();
  const pending = stream.next();
  console.detach();
  await assert.rejects(pending, (error) => error.category === "detached");
  const other = await machine.console.attach({ generation: 1 });
  const controller = new AbortController();
  const reason = new Error("stop observing");
  const waiting = other.follow({ signal: controller.signal }).next();
  controller.abort(reason);
  await assert.rejects(waiting, (error) => error === reason);
});

function eventPage(after, values) {
  const events = values.map((value, index) => {
    const cursor = after + index + 1;
    return { cursor, value, digest: sandsurfDigest("operation", ["sandsurf-runtime-event-v1", "box", cursor, value]) };
  });
  const cursor = after + values.length;
  return { kind: "runtime", response: { kind: "events", page: { cursor, available: cursor, events } } };
}

test("event followers use one resumable stream with page backpressure, not polling", async () => {
  const calls = [];
  let resumed = 0;
  let detached = false;
  const machine = fixtureMachine(async () => { throw new Error("stream performed an RPC poll"); }, 1, undefined,
    async function* (id, after, maximum) {
      calls.push({ id, after, maximum });
      try {
        yield eventPage(after, [{ kind: "receipt", executionId: "one", receiptDigest: "a".repeat(64) }, { kind: "receipt", executionId: "two", receiptDigest: "b".repeat(64) }]);
        resumed++;
        yield eventPage(after + 2, []);
      } finally { detached = true; }
    });
  const stream = machine.events.follow({ after: 5, maximum: 2 });
  assert.equal((await stream.next()).value.cursor, 6);
  assert.equal(resumed, 0);
  assert.equal((await stream.next()).value.cursor, 7);
  assert.equal(resumed, 0);
  await stream.return();
  assert.equal(detached, true);
  assert.deepEqual(calls, [{ id: "box", after: 5, maximum: 2 }]);
});

test("event streams reject gaps, changed digests, and impossible page boundaries", async () => {
  const valid = eventPage(0, [{ kind: "receipt", executionId: "one", receiptDigest: "a".repeat(64) }]);
  for (const mutate of [
    (page) => { page.events[0].digest = "b".repeat(64); },
    (page) => { page.events[0].digest = "malformed"; },
    (page) => { page.events[0].value.invalid = 1.5; },
    (page) => { page.events[0].cursor = 2; },
    (page) => { page.cursor = 2; },
    (page) => { page.available = 0; },
  ]) {
    const response = structuredClone(valid);
    mutate(response.response.page);
    const machine = fixtureMachine(async () => { throw new Error("stream performed an RPC poll"); }, 1, undefined,
      async function* () { yield response; });
    await assert.rejects(machine.events.follow().next(), (error) => error.category === "protocol");
  }
});

test("retained events expose typed facts and reject digest-valid malformed reports", async () => {
  const command = createSandsurfGuestCommand({ machineId: "box", generation: 1, operationId: "spawn-command", request: { kind: "spawn", request: executionRequest() } });
  const configuration = fixtureView().runtimeConfiguration;
  const delivered = { command: { machineId: "box", operationId: "configure", revision: 2, requestDigest: "c".repeat(64), configuration },
    delivery: "unknown", evidenceDigest: null, observation: null };
  const values = [
    { kind: "machine", observation: fixtureView().machine.value },
    { kind: "guest-operation", operation: { admission: { request: command, binary: null }, delivery: "unknown", evidenceDigest: null } },
    { kind: "configuration-operation", operation: delivered },
    { kind: "lifecycle-operation", operation: { ...delivered, command: { ...delivered.command, desired: "running" } } },
    { kind: "process", process: { request: executionRequest(), guestPid: 23, state: { kind: "running" }, lineage: null } },
    { kind: "output", executionId: "command", boundary: completedState().output },
    { kind: "receipt", executionId: "command", receiptDigest: "a".repeat(64) },
    { kind: "evidence-release", executionId: "command", requestDigest: "b".repeat(64), cleanupPending: true },
  ];
  const machine = fixtureMachine(async () => eventPage(0, values));
  const page = await machine.events.read();
  assert.equal(page.events.length, 8);
  assert.equal(page.events[1].value.operation.owner, "guardian-journal");
  assert.equal(page.events[1].value.operation.observation.delivery, "unknown");
  assert.equal(page.events[2].value.operation.observation, null, "unknown installation cannot invent completion");
  assert.equal(page.events[3].value.operation.desired, "running");
  assert.equal(page.events[4].value.kind, "execution");
  assert.equal(page.events[4].value.execution.state.kind, "running");
  assert.equal("accepted" in page.events[6].value, false);
  assert.equal(page.events[7].value.cleanupPending, true);
  const malformed = [
    { ...values[0], observation: { ...values[0].observation, machineId: "other" } },
    { ...values[1], operation: { ...values[1].operation, delivery: "successful" } },
    { ...values[2], operation: { ...delivered, observation: { machineId: "other", generation: 1, sequence: 1, digest: "a".repeat(64) } } },
    { ...values[3], operation: { ...values[3].operation, command: { ...values[3].operation.command, desired: "healthy" } } },
    { ...values[4], process: { ...values[4].process, request: { ...executionRequest(), machineId: "other" } } },
    { ...values[5], boundary: { ...completedState().output, stdoutBytes: 1 } },
    { ...values[6], accepted: true },
    { ...values[7], cleanupPending: "false" },
    { kind: "health", healthy: true },
  ];
  for (const value of malformed) {
    const malformedMachine = fixtureMachine(async () => eventPage(0, [value]));
    await assert.rejects(malformedMachine.events.read(), (error) => error.category === "protocol");
  }
});

function fixtureView(generation = 1) {
  const diskBytes = 1024 ** 3;
  const outputBytes = 1024 ** 2;
  const snapshotBytes = 2 * (diskBytes + 512 * 1024 ** 2 + 64 * 1024 ** 2);
  return {
    id: "box", imageDigest: "a".repeat(64), knownSensitive: false,
    runtimeConfiguration: { network: { rules: [] }, exposures: [], resources: {
      vcpus: 1, memoryMiB: 512, diskBytes, outputBytes, managedExecutions: 64,
      cpuQuotaMicros: 100_000, hostOverheadBytes: 512 * 1024 ** 2,
      snapshotBytes, physicalStorageBytes: 2 * diskBytes + outputBytes + snapshotBytes + 64 * 1024 ** 2,
      channels: 32, inflightRequests: 16, networkConnections: 256,
      networkBytesPerSecond: 64 * 1024 ** 2, networkQueueBytes: 16 * 1024 ** 2,
    } },
    configurationRevision: 99, reservation: "held", lifecycleIntent: { machineId: "box", operationId: "create", desired: "running", revision: 99, requestDigest: "a".repeat(64), completion: null }, machine: { kind: "current", value: { machineId: "box", generation, sequence: 1, state: "running", appliedRevision: 99, cause: { kind: "lifecycle", operationId: "create" }, evidenceDigest: "b".repeat(64) } },
    storage: { kind: "current", phase: "published", capacityBytes: 1024 ** 3, operationId: null, payload: { kind: "present", fileBytes: 1024 ** 3 } },
    management: { kind: "unavailable", lastKnown: null },
    executionDefaults: { environment: {}, user: "agent", workingDirectory: "/workspace" },
    lifetime: { expiresAtUnixMillis: null, expirationAction: "stop" }, lastActivityUnixMillis: 1,
  };
}

test("machine inspection decodes each ownership dimension without forwarding raw host records", async () => {
  const view = fixtureView();
  view.management = { kind: "current", value: { generation: 1, identity: { bootId: "boot", instanceId: "daemon" }, observedUnixMillis: 10 } };
  view.internalAuthority = { signingKey: "never-public" };
  const machine = fixtureMachine(async () => ({ kind: "machine", value: view }));
  const inspection = await machine.inspect();
  assert.equal(inspection.machine.value.state, "running");
  assert.equal(inspection.lifecycleIntent.completion, null);
  assert.equal(inspection.management.value.identity.instanceId, "daemon");
  assert.equal("internalAuthority" in inspection, false);
  assert.equal("resources" in inspection, false, "runtime configuration is the sole authorized envelope representation");
  assert.equal(inspection.runtimeConfiguration.resources.memoryMiB, 512);
  view.management = { kind: "unavailable", lastKnown: view.management.value };
  const disconnected = await machine.inspect();
  assert.equal(disconnected.machine.value.state, "running", "management loss does not establish native stop");
  assert.equal(disconnected.management.lastKnown.identity.instanceId, "daemon");
  for (const change of [
    { knownSensitive: "false" }, { reservation: "active" }, { imageDigest: "invalid" }, { configurationRevision: 0 },
    { management: { kind: "current", value: { ...inspection.management.value, generation: 0 } } },
    { management: { kind: "current", value: { ...inspection.management.value, identity: { bootId: "boot", instanceId: "bad/id" } } } },
    { executionDefaults: { environment: { PATH: 5 }, user: "agent", workingDirectory: "/home/agent" } },
    { lifecycleIntent: { ...view.lifecycleIntent, revision: 100 } },
  ]) {
    const malformed = fixtureMachine(async () => ({ kind: "machine", value: { ...view, ...change } }));
    await assert.rejects(malformed.inspect(), (error) => error.category === "protocol");
  }
  const host = new Sandsurf({ request: async () => ({ kind: "machine", value: fixtureView() }) }, () => true);
  await assert.rejects(host.machines.connect("different"), (error) => error.category === "protocol");
});

test("rollback returns a reconnectable host operation without replacing machine or execution handles", async () => {
  const requests = [];
  const value = { operationId: "rollback", machineId: "box", snapshotId: "snapshot", expectedRevision: 99, requestDigest: "a".repeat(64), phase: "admitted", evidenceDigest: null };
  const host = new Sandsurf({ request: async (request) => {
    requests.push(request);
    if (request.kind === "rollback-filesystem") return { kind: "rollback", value };
    return { kind: "host-operation", value: { kind: "rollback", value: { ...value, phase: "applied", evidenceDigest: "b".repeat(64) } } };
  } }, () => true);
  const machine = new Machine(host, fixtureView());
  const operation = await machine.snapshots.rollback("snapshot", { operationId: "rollback" });
  assert.ok(operation instanceof Operation);
  assert.equal(operation.observation.observation.phase, "admitted");
  assert.equal((await operation.inspect()).observation.phase, "applied");
  assert.equal(machine.generation, 1, "operation observation cannot fabricate native restore or rebind a machine");
  assert.equal(requests[1].kind, "get-operation");
  assert.equal(requests[1].machineId, "box");
});

test("authority-changing responses advance cached revisions without inspection", async () => {
  let view = fixtureView();
  const requests = [];
  const exposure = { id: "web", machineId: "box", revision: 102,
    spec: { guestAddress: "100.64.0.2", guestPort: 8080, hostAddress: "127.0.0.1", hostPort: 8080, public: false },
    active: true, boundPort: 8080 };
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    if (request.kind === "get-machine") return { kind: "machine", value: view };
    assert.equal(request.expectedRevision, view.configurationRevision);
    view = { ...view, configurationRevision: view.configurationRevision + 1 };
    if (request.kind === "set-exposure") return { kind: "exposure", machine: view, exposure };
    if (request.kind === "lifecycle") return { kind: "lifecycle", machine: view, operation: { delivery: "applied" } };
    if (request.kind === "update-resources") return { kind: "resource-update", machine: view,
      assessment: { mode: "live", reasons: [] } };
    return { kind: "configuration", machine: view };
  }, 1, async () => true);
  const original = view;
  await machine.network.denyAll({ operationId: "network" });
  await machine.resources.update(view.runtimeConfiguration.resources, { operationId: "resources" });
  await machine.ports.expose({ guestPort: 8080 }, { id: "web", operationId: "expose" });
  await machine.powerOff({ operationId: "stop" });
  assert.equal(machine.revision, 103);
  assert.deepEqual(requests.map((request) => request.kind), ["set-network-policy", "update-resources", "set-exposure", "lifecycle"]);
  view = { ...view, machine: fixtureView(2).machine };
  await machine.inspect();
  assert.equal(machine.generation, 2);
  // A delayed response is an observation, not permission to rewind authority.
  view = original;
  await machine.inspect();
  assert.equal(machine.revision, 103);
  assert.equal(machine.generation, 2);
});

test("native observations preserve host intent and reject fictitious command attribution", async () => {
  let view = fixtureView();
  view = { ...view, lifecycleIntent: { ...view.lifecycleIntent, desired: "running" }, machine: { kind: "current", value: { ...view.machine.value, state: "stopped", sequence: 2, cause: { kind: "native" } } } };
  const machine = fixtureMachine(async () => ({ kind: "machine", value: view }));
  const measured = await machine.inspect();
  assert.equal(measured.machine.value.state, "stopped");
  assert.equal(measured.machine.value.cause.kind, "native");
  assert.equal(measured.lifecycleIntent.desired, "running");
  assert.equal(machine.revision, 99);
  const lastKnown = measured.machine.value;
  view = { ...view, machine: { kind: "unavailable", lastKnown } };
  assert.deepEqual((await machine.inspect()).machine, view.machine);
  assert.equal(machine.generation, undefined, "a cached measurement cannot assert current reachability");
  view = { ...view, machine: { kind: "current", value: { ...lastKnown, cause: { kind: "native", operationId: "pretend-command" } } } };
  await assert.rejects(machine.inspect(), /observation cause/u);
});

test("host power support is distinct from qualification and malformed claims are rejected", async () => {
  const unqualified = { kind: "unqualified", reasons: ["no hardware qualification"] };
  let value = {
    hostId: "host", platform: "linux", architecture: "x86_64", guestArchitecture: "amd64", guestPlatform: "linux/amd64", engine: "firecracker",
    lifecycle: unqualified, fullState: { kind: "supported", qualification: unqualified }, images: unqualified, defaultImageDigest: null,
    imageWorkers: { kind: "supported", qualification: unqualified },
    networkEgress: { kind: "unsupported", reasons: ["kernel boundary not installed"] },
    console: { kind: "supported", qualification: unqualified },
    resources: Object.fromEntries(["nativeTopology", "cpuTime", "aggregateHostMemory", "managedAdmission",
      "outputRetention", "storageReservations", "networkEnvelope", "aggregatePhysicalStorage", "sharedHostWorkers",
      "completeEnforcement"].map((name) => [name, { kind: "unsupported", reasons: ["fixture mechanism not installed"] }])),
    qualificationRecords: [], qualificationIssues: [],
    guestPower: { shutdown: { kind: "unsupported", reasons: ["no ACPI"] }, reboot: { kind: "unsupported", reasons: ["no reset recovery"] } },
  };
  const host = new Sandsurf({ request: async () => ({ kind: "inspection", value }) });
  assert.deepEqual((await host.inspect()).guestPower, value.guestPower);
  assert.deepEqual((await host.inspect()).fullState, value.fullState);
  assert.deepEqual((await host.inspect()).networkEgress, value.networkEgress);
  const networkEgress = value.networkEgress;
  for (const claim of [undefined, { kind: "supported" }, { kind: "unsupported", reasons: [] }]) {
    value = { ...value, networkEgress: claim };
    await assert.rejects(host.inspect(), SandsurfHostError);
  }
  value = { ...value, networkEgress };
  value = { ...value, fullState: { kind: "unsupported", reasons: ["native device state cannot be restored"] } };
  assert.deepEqual((await host.inspect()).fullState, value.fullState);
  value = { ...value, fullState: unqualified };
  await assert.rejects(host.inspect(), SandsurfHostError);
  value = { ...value, fullState: { kind: "supported", qualification: unqualified } };
  value = { ...value, guestPower: { ...value.guestPower, shutdown: { kind: "supported", qualification: unqualified } } };
  assert.deepEqual((await host.inspect()).guestPower.shutdown, { kind: "supported", qualification: unqualified });
  for (const claim of [
    { kind: "unqualified", reasons: ["not a support status"] },
    { kind: "supported" },
    { kind: "unsupported", reasons: ["missing device"], qualification: unqualified },
    { kind: "unsupported", reasons: [] },
    { kind: "supported", qualification: { kind: "qualified", evidence: "not-a-digest" } },
  ]) {
    value = { ...value, guestPower: { ...value.guestPower, shutdown: claim } };
    await assert.rejects(host.inspect(), SandsurfHostError);
  }
});

test("OCI conversion binds explicit boot artifacts into approval and admission", async () => {
  const requests = [];
  const approvals = [];
  const image = { digest: "b".repeat(64), sourceDigest: "c".repeat(64),
    platform: "linux", architecture: "amd64", logicalBytes: 1024,
    storageBytes: 1024, provenanceDigest: "d".repeat(64), sensitive: false };
  const host = new Sandsurf({ request: async (request) => {
    requests.push(request);
    assert.equal(request.kind, "import-oci");
    return { kind: "image-import", operation: { image } };
  } }, async (change) => { approvals.push(change); return true; });
  const options = { source: { kind: "layout", path: "/images/source" },
    platform: "linux/amd64", operationId: "build-machine",
    recipe: { bootImage: "a".repeat(64) } };
  assert.equal((await host.images.importOCI(options)).id, image.digest);
  assert.deepEqual(requests[0].recipe, { bootImageDigest: "a".repeat(64) });
  assert.deepEqual(approvals[0].request.recipe, requests[0].recipe);
  await assert.rejects(host.images.importOCI({ ...options, recipe: undefined }), TypeError);
  assert.equal(requests.length, 1);
  assert.equal(approvals.length, 1);
});

test("native image import binds immutable input authority and rejects mismatched publication", async () => {
  const requests = [];
  const approvals = [];
  let image = { digest: "a".repeat(64), sourceDigest: "b".repeat(64), platform: "linux", architecture: "amd64",
    logicalBytes: 1024, storageBytes: 1024, provenanceDigest: "c".repeat(64), sensitive: true };
  const host = new Sandsurf({ request: async (request) => {
    requests.push(request);
    return { kind: "image-import", operation: { image } };
  } }, async (change) => { approvals.push(change); return true; });
  const manifestPath = process.platform === "win32" ? "C:\\images\\manifest.json" : "/images/manifest.json";
  const options = { manifestPath, manifestDigest: image.digest, operationId: "native-image" };
  assert.equal((await host.images.importNative(options)).id, image.digest);
  assert.deepEqual(approvals[0].request, { manifestPath, manifestDigest: image.digest });
  assert.deepEqual(requests[0], { kind: "import-native-image", manifestPath,
    manifestDigest: image.digest, operationId: "native-image", approvalId: requests[0].approvalId });
  for (const invalid of [{ ...options, manifestPath: "relative/manifest.json" },
    { ...options, manifestPath: `${manifestPath}\0` }, { ...options, manifestDigest: "not-a-digest" }]) {
    await assert.rejects(host.images.importNative(invalid), TypeError);
  }
  assert.equal(approvals.length, 1);
  assert.equal(requests.length, 1);
  image = { ...image, digest: "d".repeat(64) };
  await assert.rejects(host.images.importNative(options), /native image import identity/u);
  const denied = new Sandsurf({ request: async () => { throw new Error("denied import reached transport"); } }, () => false);
  await assert.rejects(denied.images.importNative(options), (error) => error.category === "authorization");
});

test("unapplied lifecycle retains host intent revision without inventing completion", async () => {
  const requests = [];
  const view = fixtureView();
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    return { kind: "lifecycle", machine: { ...view, configurationRevision: request.expectedRevision + 1 },
      operation: { delivery: request.desired === "paused" ? "not-applied" : "applied" } };
  }, 1, async () => true);
  await assert.rejects(machine.pause(), (error) => error.category === "not-applied");
  assert.equal(machine.revision, 100);
  await machine.powerOff();
  assert.equal(requests[1].expectedRevision, 100);
  assert.equal(machine.revision, 101);
});

test("output sealing does not require a receipt or live machine revision", async () => {
  const requests = [];
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    assert.equal("expectedRevision" in request, false);
    if (request.kind === "seal-output") return { kind: "runtime", response: { kind: "output-segment", segment: {
      id: request.segmentId, machineId: request.machineId, executionId: request.executionId, generation: 1,
      output: { finalCursor: 0, chunks: 0, stdoutBytes: 0, stderrBytes: 0, terminalBytes: 0, omittedBytes: 0, finalHash: "c".repeat(64) },
    } } };
    return { kind: "runtime", response: request.kind === "release-evidence"
      ? { kind: "release", status: { requestDigest: "a".repeat(64), cleanupPending: false } }
      : { kind: "complete" } };
  });
  const execution = new Execution(machine, "retained", 1);
  await execution.acknowledge("b".repeat(64));
  await execution.output.seal("retained-copy");
  await execution.release({ digest: "b".repeat(64), receipt: { output: {} } },
    { kind: "continuing-retention", segment: "retained-copy" });
  assert.deepEqual(requests.map((request) => request.kind), ["acknowledge-receipt", "seal-output", "release-evidence"]);
  assert.equal(requests[1].expected, null);
  assert.equal(requests[1].generation, 1);
  assert.equal("receiptDigest" in requests[1], false);
});

test("ordinary command and file queries use cached generations without grants or inspection", async () => {
  const requests = [];
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    if (request.kind === "guest") return { kind: "guest", response: { kind: "file", response: { kind: "stat", value: { kind: "regular", size: 10, readonly: false, modifiedMillis: null, mode: 0o100644, device: 1, inode: 2 } } } };
    if (request.kind === "dispatch-guest") return { kind: "dispatch", operation: { delivery: "applied" } };
    throw new Error(`unexpected round trip: ${request.kind}`);
  });
  const execution = await machine.executions.start({ argv: ["/bin/true"], executionId: "command", operationId: "start" });
  await machine.fs.stat("/etc/passwd");
  await execution.input.write(Uint8Array.of(1), { operationId: "input" });
  assert.deepEqual(requests.map((request) => request.kind), ["dispatch-guest", "guest", "dispatch-guest"]);
  for (const request of requests) {
    assert.equal(request.generation, 1);
    assert.equal("expectedRevision" in request, false);
    assert.equal("grantId" in request, false);
    assert.equal("scopeDigest" in request, false);
  }
  assert.deepEqual(requests[0].request.request.environment, {});
  for (const legacy of ["request", "hostRequest", "guest", "workload"]) assert.equal(legacy in machine, false);
});

test("filesystem handles return typed byte-preserving observations and reject malformed metadata", async () => {
  const metadata = { kind: "regular", size: 2, readonly: false, modifiedMillis: null, mode: 0o100644, device: 1, inode: 2 };
  let response = { kind: "stat", value: metadata };
  const machine = fixtureMachine(async () => ({ kind: "guest", response: { kind: "file", response } }));
  assert.deepEqual(await machine.fs.stat("/file"), metadata);
  response = { kind: "list", page: { entries: [{ name: [255, 97], stat: metadata }], next: [255, 97] } };
  const page = await machine.fs.list("/");
  assert.deepEqual(page.entries[0].name, Uint8Array.of(255, 97));
  assert.deepEqual(page.next, Uint8Array.of(255, 97));
  for (const name of [[0], [47], [256], [46], [46, 46]]) {
    response = { kind: "list", page: { entries: [{ name, stat: metadata }], next: null } };
    await assert.rejects(machine.fs.list("/"), (error) => error.category === "protocol");
  }
  for (const value of [{ ...metadata, readonly: "false" }, { ...metadata, inode: -1 }, { ...metadata, forged: true }]) {
    response = { kind: "stat", value };
    await assert.rejects(machine.fs.stat("/file"), (error) => error.category === "protocol");
  }
});

test("file range observations validate credit and complete coverage before returning bytes", async () => {
  let range = { offset: 1, bytes: [255], eof: true, observation: { size: 2, token: "a".repeat(64) } };
  const machine = fixtureMachine(async () => ({ kind: "guest", response: { kind: "file", response: { kind: "read", range } } }));
  assert.deepEqual((await machine.fs.read("/file", { offset: 1, maximum: 1 })).bytes, Uint8Array.of(255));
  for (const invalid of [{ ...range, offset: 0 }, { ...range, bytes: [256] }, { ...range, bytes: [1, 2] }, { ...range, eof: false }]) {
    range = invalid;
    await assert.rejects(machine.fs.read("/file", { offset: 1, maximum: 1 }), (error) => error.category === "protocol");
  }
});

test("filesystem acknowledgements, pagination and symlink bytes are validated before success", async () => {
  let response = { kind: "link", target: [46, 46, 47, 255] };
  const machine = fixtureMachine(async (request) => {
    if (request.kind === "dispatch-guest") return { kind: "dispatch", operation: { delivery: "applied", admission: { request: { requestDigest: "a".repeat(64) } } } };
    return { kind: "guest", response: { kind: "file", response } };
  });
  assert.deepEqual(await machine.fs.readlink("/link"), Uint8Array.of(46, 46, 47, 255));
  for (const target of [[], [0], [-1], [256], [1.5]]) {
    response = { kind: "link", target };
    await assert.rejects(machine.fs.readlink("/link"), (error) => error.category === "protocol");
  }
  response = { kind: "stat", value: {} };
  await assert.rejects(machine.fs.mkdir("/new"), (error) => error.category === "protocol");
  response = { kind: "complete", extra: true };
  await assert.rejects(machine.fs.mkdir("/new"), (error) => error.category === "protocol");
  response = { kind: "complete" };
  await machine.fs.mkdir("/new");
  await assert.rejects(machine.fs.symlink("/link", Uint8Array.of(0)), TypeError);
  const stat = { kind: "regular", size: 1, readonly: false, modifiedMillis: null, mode: 0o100644, device: 1, inode: 2 };
  for (const page of [
    { entries: [{ name: [98], stat }, { name: [97], stat }], next: null },
    { entries: [{ name: [97], stat }, { name: [97], stat }], next: null },
    { entries: [{ name: [97], stat }], next: [98] },
    { entries: [], next: [97] },
  ]) {
    response = { kind: "list", page };
    await assert.rejects(machine.fs.list("/"), (error) => error.category === "protocol");
  }
  response = { kind: "list", page: { entries: [{ name: [97], stat }], next: null } };
  await assert.rejects(machine.fs.list("/", { after: Uint8Array.of(98) }), (error) => error.category === "protocol");
});

test("watcher polling keeps its admitted generation and validates guest event identity", async () => {
  const requests = [];
  const view = fixtureView(2);
  let event = { watcherId: "watcher", generation: 1, sequence: 1, kind: "overflow", path: null };
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    if (request.kind === "get-machine") return { kind: "machine", value: view };
    if (request.kind === "dispatch-guest") return { kind: "dispatch", operation: { delivery: "applied", admission: { request: { requestDigest: "a".repeat(64) } } } };
    if (request.request.kind === "operation") return { kind: "guest", response: { kind: "file", response: { kind: "complete" } } };
    return { kind: "guest", response: { kind: "file", response: { kind: "watch", page: { events: [event], cursor: event.sequence } } } };
  });
  const watcher = await machine.fs.watch("/", { watcherId: "watcher" });
  await machine.inspect();
  assert.equal((await watcher.poll())[0].kind, "overflow");
  assert.equal(requests.at(-1).generation, 1, "a watcher cannot adopt the new cached generation");
  for (const invalid of [{ ...event, watcherId: "other" }, { ...event, generation: 2 }, { ...event, sequence: 0 }, { ...event, path: [47] }]) {
    event = invalid;
    await assert.rejects(watcher.poll(), (error) => error.category === "protocol");
  }
});

test("watcher cursors survive lost responses and SDK reconnection without claiming authority", async () => {
  const requests = [];
  let loseResponse = true;
  let invalidCursor = false;
  let invalidGap = false;
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    assert.equal(request.generation, 1);
    const after = request.request.request.after;
    if (loseResponse) { loseResponse = false; throw new Error("response lost"); }
    const events = after === 0 ? [{ watcherId: "watcher", generation: 1, sequence: invalidGap ? 2 : 1, kind: "created", path: [47, 120] }] : [];
    return { kind: "guest", response: { kind: "file", response: { kind: "watch", page: { events, cursor: invalidCursor ? 9 : (events.at(-1)?.sequence ?? after) } } } };
  });
  const watcher = machine.fs.attachWatcher({ id: "watcher", generation: 1, cursor: 0 });
  await assert.rejects(watcher.poll(), /response lost/);
  assert.equal(watcher.identity.cursor, 0);
  assert.equal((await watcher.poll()).length, 1);
  assert.deepEqual(requests.slice(0, 2).map((request) => request.request.request.after), [0, 0]);
  const reconnected = machine.fs.attachWatcher(watcher.identity);
  assert.deepEqual(await reconnected.poll(), []);
  assert.equal(requests.at(-1).request.request.after, 1);
  invalidCursor = true;
  await assert.rejects(reconnected.poll(), (error) => error.category === "protocol");
  assert.equal(reconnected.identity.cursor, 1);
  invalidCursor = false; invalidGap = true;
  await assert.rejects(machine.fs.attachWatcher({ id: "watcher", generation: 1, cursor: 0 }).poll(), (error) => error.category === "protocol");
});

test("storage inspection does not collapse unavailable native power into missing storage", async () => {
  const view = { ...fixtureView(), machine: { kind: "unavailable", lastKnown: null }, management: { kind: "unavailable", lastKnown: null } };
  const machine = fixtureMachine(async () => ({ kind: "machine", value: view }));
  assert.equal((await machine.inspect()).storage.phase, "published");
  view.storage = { kind: "current", phase: "published", capacityBytes: 4096, operationId: null, payload: { kind: "capacity-mismatch", fileBytes: 7 } };
  assert.equal((await machine.inspect()).storage.payload.kind, "capacity-mismatch");
  view.storage = { kind: "unavailable", reason: "ownership-invalid" };
  assert.equal((await machine.inspect()).storage.reason, "ownership-invalid");
  for (const invalid of [{ kind: "current", phase: "healthy" }, { kind: "unavailable", reason: "guest-fs-corrupt" }, { kind: "unavailable", reason: "ownership-missing", forged: true }]) {
    view.storage = invalid;
    await assert.rejects(machine.inspect(), (error) => error.category === "protocol");
  }
});

test("output segment handles reconnect directly and validate their immutable capture metadata", async () => {
  const requests = [];
  const boundary = { finalCursor: 3, chunks: 1, stdoutBytes: 3, stderrBytes: 0, terminalBytes: 0, omittedBytes: 0, finalHash: "c".repeat(64) };
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    return { kind: "runtime", response: { kind: "output-segment", segment: {
      id: request.segmentId, machineId: request.machineId, executionId: "archived-execution", generation: 1, output: boundary,
    } } };
  });
  const segment = machine.outputSegment("captured-prefix");
  assert.deepEqual((await segment.inspect()).output, boundary);
  assert.deepEqual(requests.map((request) => request.kind), ["get-output-segment"]);
  const execution = new Execution(machine, "archived-execution", 1);
  await assert.rejects(execution.output.seal("invalid-prefix", { boundary: { ...boundary, finalCursor: -1 } }));
  assert.equal(requests.length, 1, "invalid capture bounds must not reach the host");
});

test("stale execution handles retain their generation and cannot be manually rebound", async () => {
  const requests = [];
  const machine = fixtureMachine(async (request) => { requests.push(request); return { kind: "dispatch", operation: { delivery: "applied" } }; }, 7);
  const execution = new Execution(machine, "old-command", 3);
  await execution.signal(15, { operationId: "old-signal" });
  assert.equal(requests[0].generation, 3);
  await assert.rejects(execution.input.write(Uint8Array.of(1), { expectedGeneration: 7 }), (error) => error.category === "stale-generation");
  assert.equal(requests.length, 1);
});

test("filesystem directory views preserve Linux resolution and never expand authority", async () => {
  const paths = [];
  const machine = fixtureMachine(async (request) => {
    assert.equal(request.kind, "guest");
    assert.equal(request.generation, 1);
    paths.push(Buffer.from(request.request.request.path));
    return { kind: "guest", response: { kind: "file", response: { kind: "stat", value: { kind: "regular", size: 10, readonly: false, modifiedMillis: null, mode: 0o100644, device: 1, inode: 2 } } } };
  });
  await machine.fs.at("/home/agent").stat("linked/../file");
  await machine.fs.at("/home/agent").at("project").stat("./file");
  await machine.fs.at("/home/agent").stat("/etc//passwd");
  await machine.fs.at("/home/agent").stat(Uint8Array.of(0xff));
  assert.deepEqual(paths, [Buffer.from("/home/agent/linked/../file"),
    Buffer.from("/home/agent/project/./file"), Buffer.from("/etc//passwd"),
    Buffer.concat([Buffer.from("/home/agent/"), Buffer.from([0xff])])]);
});

test("filesystem streaming holds one generation and enforces its byte bound", async () => {
  const bytes = Buffer.from("binary\0file");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const requests = [];
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    const { offset, maximum } = request.request.request;
    const chunk = bytes.subarray(offset, offset + maximum);
    return { kind: "guest", response: { kind: "file", response: { kind: "read",
      range: { offset, bytes: [...chunk], eof: offset + chunk.length === bytes.length,
        observation: { size: bytes.length, token: "a".repeat(64) } } } } };
  }, 3);
  const chunks = [];
  for await (const chunk of machine.fs.at("/home/agent").readStream("data", { chunkBytes: 3, expectedDigest: digest })) chunks.push(chunk);
  assert.deepEqual(Buffer.concat(chunks), bytes);
  assert.ok(requests.every((request) => request.generation === 3));
  await assert.rejects(machine.fs.readFile("/data", { expectedDigest: "b".repeat(64) }), (error) => error.category === "integrity");
  await assert.rejects(machine.fs.readFile("/data", { maximumBytes: 2 }), (error) => error.category === "capacity");
});

test("ambiguous guest admission is never reported as a completed execution", async () => {
  for (const delivery of ["unknown", "not-applied"]) {
    const machine = fixtureMachine(async () => ({ kind: "dispatch", operation: { delivery } }));
    await assert.rejects(machine.executions.start({ argv: ["/bin/true"], operationId: "stable-command" }),
      (error) => error instanceof SandsurfHostError && error.category === (delivery === "unknown" ? "ambiguous" : "not-applied"));
  }
});

test("filesystem failures retain their structured category", async () => {
  const machine = fixtureMachine(async () => ({ kind: "guest", response: { kind: "error", code: "filesystem.missing", message: "file does not exist" } }));
  await assert.rejects(machine.fs.stat("/missing"), (error) => error.category === "filesystem.missing");
});

test("streamed writes have chunk-boundary-independent identities and preserve ambiguous stages", async () => {
  const bytes = Buffer.alloc(70_001, 0x5a);
  const expectedDigest = createHash("sha256").update(bytes).digest("hex");
  const run = async (chunks, failChunk = false) => {
    const operations = [];
    const machine = fixtureMachine(async (request) => {
      if (request.kind === "dispatch-guest") {
        operations.push({ operationId: request.operationId, request: request.request });
        return { kind: "dispatch", operation: { delivery: "applied", admission: { request: { requestDigest: "a".repeat(64) } } } };
      }
      if (request.kind === "guest") {
        if (failChunk && operations.at(-1)?.request.request.kind === "write-chunk") throw new SandsurfHostError("transport", "ambiguous delivery");
        const response = operations.at(-1)?.request.request.kind === "commit-write"
          ? { kind: "written", revision: { size: bytes.byteLength, digest: expectedDigest } }
          : { kind: "complete" };
        return { kind: "guest", response: { kind: "file", response } };
      }
      throw new Error(`unexpected request: ${request.kind}`);
    });
    const pending = machine.fs.writeStream("/workspace/data", chunks, { length: bytes.byteLength, digest: expectedDigest, operationId: "stable-write", transferId: "stable-transfer" });
    if (failChunk) await assert.rejects(pending, /ambiguous delivery/u);
    else await pending;
    return operations;
  };
  const first = await run([bytes.subarray(0, 10_000), bytes.subarray(10_000)]);
  const second = await run([bytes.subarray(0, 1), bytes.subarray(1, 65_537), bytes.subarray(65_537)]);
  assert.deepEqual(first, second);
  const interrupted = await run([bytes], true);
  assert.equal(interrupted.some(({ request }) => request.request.kind === "abort-write"), false);
});

test("leader exit and output capture are independent boundaries", async () => {
  const request = executionRequest();
  let captured = false;
  let receiptPublished = false;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") {
      assert.equal(query.after, 0, "wait performed an RPC poll");
      return eventPage(0, [{ kind: "machine", observation: fixtureView().machine.value }]);
    }
    if (query.kind === "get-process") return { kind: "runtime", response: { kind: "process", process: { lineage: null, executionId: "command", generation: 1, interruption: null, report: { kind: "current", value: { request, guestPid: 23, lineage: null, state: { kind: "draining", outcome: { kind: "exit", code: 0 }, accountingDigest: "c".repeat(64) } } } } } };
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", ...(receiptPublished ? executionReceipt() : { receipt: null, digest: null }) } };
    throw new Error(`unexpected request: ${query.kind}`);
  }, 1, undefined, async function* (_id, after) {
    assert.equal(after, 1);
    captured = true;
    yield eventPage(1, [{ kind: "process", process: { request, guestPid: 23, lineage: null, state: completedState() } }]);
    receiptPublished = true;
    yield eventPage(2, [{ kind: "receipt", executionId: "command", receiptDigest: "b".repeat(64) }]);
  });
  const execution = new Execution(machine, "command", 1);
  assert.equal((await execution.waitLeader()).state.kind, "draining");
  assert.equal(captured, false);
  assert.equal((await execution.waitCapture()).state.kind, "exited");
});

test("waiting through unavailable management does not invent termination or replay admission", async () => {
  const request = executionRequest();
  let pages = 0;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") {
      pages++;
      assert.equal(pages, 1, "wait performed an RPC poll");
      return eventPage(0, []);
    }
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", ...(pages >= 3 ? executionReceipt() : { receipt: null, digest: null }) } };
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { lineage: null, executionId: "command", generation: 1, interruption: null, report: { kind: "unavailable", lastKnown: null } } } };
  }, 1, undefined, async function* (_id, after) {
    assert.equal(after, 0);
    pages++;
    yield eventPage(0, [{ kind: "process", process: { request, guestPid: 23, lineage: null, state: completedState() } }]);
    pages++;
    yield eventPage(1, [{ kind: "receipt", executionId: "command", receiptDigest: "b".repeat(64) }]);
  });
  assert.equal((await new Execution(machine, "command", 1).waitCapture({ signal: AbortSignal.timeout(1000) })).state.kind, "exited");
});

test("durable spawn reservations reconnect before the first guest observation", async () => {
  const request = executionRequest("terminal", "terminal");
  const machine = fixtureMachine(async (query) => {
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", request, process: { lineage: null, executionId: "terminal", generation: 1, interruption: null, report: { kind: "unavailable", lastKnown: null } } } };
  });
  assert.equal((await machine.executions.get("terminal")).generation, 1);
  const terminal = await machine.terminals.get("terminal");
  assert.equal(terminal.process.generation, 1);
  assert.equal((await terminal.process.inspect()).report.kind, "unavailable");
});

test("native interruption wakes execution waits without inventing guest exit or capture", async () => {
  const request = executionRequest();
  const lastKnown = { request, guestPid: 23, lineage: null, state: { kind: "running" } };
  const stopped = { ...fixtureView().machine.value, sequence: 2, state: "stopped", cause: { kind: "native" } };
  let interrupted = false;
  let subscriptions = 0;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") return eventPage(0, []);
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { lineage: null, executionId: "command", generation: 1,
      report: { kind: "unavailable", lastKnown }, interruption: interrupted ? stopped : null } } };
  }, 1, undefined, async function* () {
    subscriptions++;
    interrupted = true;
    yield eventPage(0, [{ kind: "machine", observation: stopped }]);
    assert.fail("interrupted wait requested another event");
  });
  const execution = new Execution(machine, "command", 1);
  const isInterruption = (error) => error instanceof ExecutionInterruptedError && error.generation === 1 && error.observation.state === "stopped";
  await assert.rejects(execution.waitLeader({ signal: AbortSignal.timeout(1000) }), isInterruption);
  await assert.rejects(execution.waitCapture({ signal: AbortSignal.timeout(1000) }), isInterruption);
  assert.equal(subscriptions, 1, "an already committed interruption must not require a subscription");
  assert.equal((await execution.inspect()).report.lastKnown.state.kind, "running");
});

test("native interruption preserves reported leader exit but never substitutes for a capture receipt", async () => {
  const request = executionRequest();
  const stopped = { ...fixtureView().machine.value, sequence: 2, state: "stopped", cause: { kind: "native" } };
  let state = { kind: "draining", outcome: { kind: "exit", code: 0 }, accountingDigest: "c".repeat(64) };
  let captured = false;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") return eventPage(0, []);
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", ...(captured ? executionReceipt() : { receipt: null, digest: null }) } };
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { lineage: null, executionId: "command", generation: 1, interruption: stopped,
      report: { kind: "unavailable", lastKnown: { request, guestPid: 23, lineage: null, state } } } } };
  });
  const execution = new Execution(machine, "command", 1);
  assert.equal((await execution.waitLeader()).state.kind, "draining");
  await assert.rejects(execution.waitCapture(), ExecutionInterruptedError);
  state = completedState();
  await assert.rejects(execution.waitCapture(), ExecutionInterruptedError);
  captured = true;
  assert.equal((await execution.waitCapture()).state.kind, "exited");
});

test("restore preserves historical admissions and exposes an independent execution incarnation", async () => {
  const request = executionRequest();
  const restored = { ...request, executionId: "restored-command", generation: 2 };
  const lineage = { logicalExecutionId: "command", sourceExecutionId: "command", sourceMachineId: "box",
    sourceGeneration: 1, snapshotId: "snapshot", outputAnchor: completedState().output };
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "dispatch-guest") {
      assert.equal(query.generation, 1, "the old handle must never borrow the restored generation");
      throw new SandsurfHostError("stale-generation", "host rejected the historical mutation");
    }
    assert.equal(query.kind, "get-process");
    const historical = query.executionId === "command";
    assert.ok(historical || query.executionId === restored.executionId);
    return { kind: "runtime", response: { kind: "process", request: historical ? request : restored,
      process: { lineage: historical ? null : lineage, executionId: query.executionId,
        generation: historical ? 1 : 2, interruption: null, report: { kind: "unavailable", lastKnown: null } } } };
  }, 2);
  const original = await machine.executions.get("command");
  assert.equal(original.generation, 1);
  assert.equal((await original.inspect()).lineage, null);
  await assert.rejects(original.terminate(), (error) => error instanceof SandsurfHostError && error.category === "stale-generation");
  const resumed = await machine.executions.get(restored.executionId);
  assert.equal(resumed.generation, 2);
  assert.deepEqual((await resumed.inspect()).lineage, lineage);
});

test("output follow yields retained bytes before reporting native interruption", async () => {
  const bytes = Buffer.from([0, 255, 128, 13, 10]);
  const stopped = { ...fixtureView().machine.value, sequence: 2, state: "stopped", cause: { kind: "native" } };
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") return eventPage(0, []);
    if (query.kind === "read-evidence") {
      const chunks = query.after === 0 ? [{ offset: 0, stream: "stdout", bytes: [...bytes], bytesDigest: createHash("sha256").update(bytes).digest("hex") }] : [];
      return { kind: "runtime", response: { kind: "output", page: { after: query.after, cursor: bytes.length, available: bytes.length, chunks } } };
    }
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", receipt: null, digest: null } };
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { lineage: null, executionId: "command", generation: 1,
      report: { kind: "unavailable", lastKnown: null }, interruption: stopped } } };
  });
  const execution = new Execution(machine, "command", 1);
  const stream = execution.output.follow();
  assert.deepEqual(Buffer.from((await stream.next()).value.bytes), bytes);
  await assert.rejects(stream.next(), ExecutionInterruptedError);
  assert.deepEqual(Buffer.from((await execution.output.read()).chunks[0].bytes), bytes);
});
