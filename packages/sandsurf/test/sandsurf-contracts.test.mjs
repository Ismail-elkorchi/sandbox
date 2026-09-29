import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { before, test } from "node:test";
import { Artifact, Machine, Execution, Sandsurf, SandsurfHostError } from "../dist/index.js";
import { createSandsurfGuestPath, createSandsurfGuestCommand, encodeSandsurfFrame, SandsurfFrameDecoder, sandsurfDigest, sandsurfGuestRequestMetadata, sandsurfGuestPathUtf8, validateSandsurfGuestPath, validateSandsurfGuestCommand, validateSandsurfRelease } from "../dist/sandsurf-protocol.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixture = resolve(root, `target/debug/examples/contract_fixture${process.platform === "win32" ? ".exe" : ""}`);
before(() => {
  const built = spawnSync("cargo", ["build", "--locked", "-p", "sandsurf-protocol", "--example", "contract_fixture"], { cwd: root, encoding: "utf8", timeout: 120_000 });
  assert.equal(built.status, 0, built.stderr);
});
function native(mode, input, ...args) { return spawnSync(fixture, [mode, ...args], { input, maxBuffer: 1024 * 1024, timeout: 10_000 }); }

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
    { kind: "continuing-retention", pin: "pin" },
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

function fixtureMachine(request, generation = 1) {
  const host = new Sandsurf({ request }, async () => { throw new Error("ordinary guest access requested host approval"); });
  return new Machine(host, {
    id: "box", imageDigest: "a".repeat(64),
    resources: { vcpus: 1, memoryMiB: 512, diskBytes: 1024 ** 3, outputBytes: 1024 ** 2, managedExecutions: 64 },
    runtimeConfiguration: { network: { rules: [] }, exposures: [], resources: { vcpus: 1, memoryMiB: 512, diskBytes: 1024 ** 3, outputBytes: 1024 ** 2, managedExecutions: 64 } },
    configurationRevision: 99, reservation: "held", lifecycleIntent: {}, machine: { kind: "current", value: { generation } },
    executionDefaults: { environment: {}, user: "agent", workingDirectory: "/workspace", entrypoint: [], command: [] },
    lifetime: { expiresAtUnixMillis: null, expirationAction: "stop" }, lastActivityUnixMillis: 1,
  });
}

test("ordinary command and file queries use cached generations without grants or inspection", async () => {
  const requests = [];
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    if (request.kind === "guest") return { kind: "guest", response: { kind: "file", response: { kind: "stat" } } };
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
    return { kind: "guest", response: { kind: "file", response: { kind: "stat" } } };
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
        return { kind: "guest", response: { kind: "file", response: { kind: "complete" } } };
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
  const request = { machineId: "box", generation: 1, executionId: "command" };
  const output = { finalCursor: 0, finalHash: "a".repeat(64) };
  let captured = false;
  let receiptPublished = false;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") {
      if (query.after === 1) captured = true;
      if (query.after === 2) receiptPublished = true;
      const events = query.after === 1 ? [{ cursor: 2, digest: "a".repeat(64), value: { kind: "process", process: { request, guestPid: 23, lineage: null, state: { kind: "exited", output } } } }] : query.after === 2 ? [{ cursor: 3, digest: "a".repeat(64), value: { kind: "receipt", executionId: "command", receiptDigest: "b".repeat(64) } }] : [];
      return { kind: "runtime", response: { kind: "events", page: { cursor: events.at(-1)?.cursor ?? 1, available: events.at(-1)?.cursor ?? 1, events } } };
    }
    if (query.kind === "get-process") return { kind: "runtime", response: { kind: "process", process: { kind: "current", value: { request, guestPid: 23, lineage: null, state: { kind: "draining", outcome: { kind: "exit", code: 0 } } } } } };
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", receipt: receiptPublished ? { ...request, output } : null, digest: receiptPublished ? "b".repeat(64) : null } };
    throw new Error(`unexpected request: ${query.kind}`);
  });
  const execution = new Execution(machine, "command", 1);
  assert.equal((await execution.waitLeader()).state.kind, "draining");
  assert.equal(captured, false);
  assert.equal((await execution.waitCapture()).state.kind, "exited");
});

test("waiting through unavailable management does not invent termination or replay admission", async () => {
  const request = { machineId: "box", generation: 1, executionId: "command" };
  const output = { finalCursor: 0, finalHash: "a".repeat(64) };
  let pages = 0;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") {
      pages++;
      const events = pages === 2 ? [{ cursor: 1, digest: "a".repeat(64), value: { kind: "process", process: { request, guestPid: 23, lineage: null, state: { kind: "exited", output } } } }] : pages === 3 ? [{ cursor: 2, digest: "a".repeat(64), value: { kind: "receipt", executionId: "command", receiptDigest: "b".repeat(64) } }] : [];
      return { kind: "runtime", response: { kind: "events", page: { cursor: events.at(-1)?.cursor ?? 0, available: 2, events } } };
    }
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", receipt: pages >= 3 ? { ...request, output } : null, digest: pages >= 3 ? "b".repeat(64) : null } };
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { kind: "unavailable", lastKnown: null } } };
  });
  assert.equal((await new Execution(machine, "command", 1).waitCapture({ signal: AbortSignal.timeout(1000) })).state.kind, "exited");
});

test("durable spawn reservations reconnect before the first guest observation", async () => {
  const request = { machineId: "box", generation: 1, executionId: "terminal", stdio: "terminal" };
  const machine = fixtureMachine(async (query) => {
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", request, process: { kind: "unavailable", lastKnown: null } } };
  });
  assert.equal((await machine.executions.get("terminal")).generation, 1);
  const terminal = await machine.terminals.get("terminal");
  assert.equal(terminal.process.generation, 1);
  assert.equal((await terminal.process.inspect()).kind, "unavailable");
});
