import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { before, test } from "node:test";
import { Artifact, Machine, Execution, ExecutionInterruptedError, Sandsurf, SandsurfHostError } from "../dist/index.js";
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

function fixtureMachine(request, generation = 1, authorizer = async () => { throw new Error("ordinary guest access requested host approval"); }, eventPages) {
  const host = new Sandsurf({ request, eventPages }, authorizer);
  return new Machine(host, fixtureView(generation));
}

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

function fixtureView(generation = 1) {
  return {
    id: "box", imageDigest: "a".repeat(64),
    resources: { vcpus: 1, memoryMiB: 512, diskBytes: 1024 ** 3, outputBytes: 1024 ** 2, managedExecutions: 64 },
    runtimeConfiguration: { network: { rules: [] }, exposures: [], resources: { vcpus: 1, memoryMiB: 512, diskBytes: 1024 ** 3, outputBytes: 1024 ** 2, managedExecutions: 64 } },
    configurationRevision: 99, reservation: "held", lifecycleIntent: {}, machine: { kind: "current", value: { machineId: "box", generation, sequence: 1, state: "running", appliedRevision: 99, cause: { kind: "lifecycle", operationId: "create" }, evidenceDigest: "b".repeat(64) } },
    management: { kind: "unavailable", lastKnown: null },
    executionDefaults: { environment: {}, user: "agent", workingDirectory: "/workspace", entrypoint: [], command: [] },
    lifetime: { expiresAtUnixMillis: null, expirationAction: "stop" }, lastActivityUnixMillis: 1,
  };
}

test("authority-changing responses advance cached revisions without inspection", async () => {
  let view = fixtureView();
  const requests = [];
  const exposure = { id: "web", machineId: "box", revision: 102,
    spec: { guestAddress: "127.0.0.1", guestPort: 8080, hostAddress: "127.0.0.1", hostPort: 8080, public: false },
    active: true, boundPort: 8080 };
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    if (request.kind === "get-machine") return { kind: "machine", value: view };
    assert.equal(request.expectedRevision, view.configurationRevision);
    view = { ...view, configurationRevision: view.configurationRevision + 1 };
    if (request.kind === "set-exposure") return { kind: "exposure", machine: view, exposure };
    if (request.kind === "lifecycle") return { kind: "lifecycle", machine: view, operation: { delivery: "applied" } };
    return { kind: "configuration", machine: view };
  }, 1, async () => true);
  const original = view;
  await machine.network.denyAll({ operationId: "network" });
  await machine.resources.update(view.resources, { operationId: "resources" });
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
  view = { ...view, lifecycleIntent: { desired: "running" }, machine: { kind: "current", value: { ...view.machine.value, state: "stopped", sequence: 2, cause: { kind: "native" } } } };
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
    lifecycle: unqualified, fullState: unqualified, images: unqualified, defaultImageDigest: null,
    guestPower: { shutdown: { kind: "unsupported", reasons: ["no ACPI"] }, reboot: { kind: "unsupported", reasons: ["no reset recovery"] } },
  };
  const host = new Sandsurf({ request: async () => ({ kind: "inspection", value }) });
  assert.deepEqual((await host.inspect()).guestPower, value.guestPower);
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

test("retained-output operations are fenced by receipts, not live machine revisions", async () => {
  const requests = [];
  const machine = fixtureMachine(async (request) => {
    requests.push(request);
    assert.equal("expectedRevision" in request, false);
    return { kind: "runtime", response: request.kind === "release-evidence"
      ? { kind: "release", status: { requestDigest: "a".repeat(64), cleanupPending: false } }
      : { kind: "complete" } };
  });
  const execution = new Execution(machine, "retained", 1);
  await execution.acknowledge("b".repeat(64));
  await execution.pin("retained-copy", "b".repeat(64));
  await execution.release({ digest: "b".repeat(64), receipt: { output: {} } },
    { kind: "continuing-retention", pin: "retained-copy" });
  assert.deepEqual(requests.map((request) => request.kind), ["acknowledge-receipt", "pin-evidence", "release-evidence"]);
});

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
      assert.equal(query.after, 0, "wait performed an RPC poll");
      return eventPage(0, [{ kind: "machine", observation: fixtureView().machine.value }]);
    }
    if (query.kind === "get-process") return { kind: "runtime", response: { kind: "process", process: { executionId: "command", generation: 1, interruption: null, report: { kind: "current", value: { request, guestPid: 23, lineage: null, state: { kind: "draining", outcome: { kind: "exit", code: 0 } } } } } } };
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", receipt: receiptPublished ? { ...request, output } : null, digest: receiptPublished ? "b".repeat(64) : null } };
    throw new Error(`unexpected request: ${query.kind}`);
  }, 1, undefined, async function* (_id, after) {
    assert.equal(after, 1);
    captured = true;
    yield eventPage(1, [{ kind: "process", process: { request, guestPid: 23, lineage: null, state: { kind: "exited", output } } }]);
    receiptPublished = true;
    yield eventPage(2, [{ kind: "receipt", executionId: "command", receiptDigest: "b".repeat(64) }]);
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
      assert.equal(pages, 1, "wait performed an RPC poll");
      return eventPage(0, []);
    }
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", receipt: pages >= 3 ? { ...request, output } : null, digest: pages >= 3 ? "b".repeat(64) : null } };
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { executionId: "command", generation: 1, interruption: null, report: { kind: "unavailable", lastKnown: null } } } };
  }, 1, undefined, async function* (_id, after) {
    assert.equal(after, 0);
    pages++;
    yield eventPage(0, [{ kind: "process", process: { request, guestPid: 23, lineage: null, state: { kind: "exited", output } } }]);
    pages++;
    yield eventPage(1, [{ kind: "receipt", executionId: "command", receiptDigest: "b".repeat(64) }]);
  });
  assert.equal((await new Execution(machine, "command", 1).waitCapture({ signal: AbortSignal.timeout(1000) })).state.kind, "exited");
});

test("durable spawn reservations reconnect before the first guest observation", async () => {
  const request = { machineId: "box", generation: 1, executionId: "terminal", stdio: "terminal" };
  const machine = fixtureMachine(async (query) => {
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", request, process: { executionId: "terminal", generation: 1, interruption: null, report: { kind: "unavailable", lastKnown: null } } } };
  });
  assert.equal((await machine.executions.get("terminal")).generation, 1);
  const terminal = await machine.terminals.get("terminal");
  assert.equal(terminal.process.generation, 1);
  assert.equal((await terminal.process.inspect()).report.kind, "unavailable");
});

test("native interruption wakes execution waits without inventing guest exit or capture", async () => {
  const request = { machineId: "box", generation: 1, executionId: "command" };
  const lastKnown = { request, guestPid: 23, lineage: null, state: { kind: "running" } };
  const stopped = { ...fixtureView().machine.value, sequence: 2, state: "stopped", cause: { kind: "native" } };
  let interrupted = false;
  let subscriptions = 0;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") return eventPage(0, []);
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { executionId: "command", generation: 1,
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
  const request = { machineId: "box", generation: 1, executionId: "command" };
  const stopped = { ...fixtureView().machine.value, sequence: 2, state: "stopped", cause: { kind: "native" } };
  const output = { finalCursor: 0, finalHash: "a".repeat(64) };
  let state = { kind: "draining", outcome: { kind: "exit", code: 0 } };
  let captured = false;
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") return eventPage(0, []);
    if (query.kind === "get-receipt") return { kind: "runtime", response: { kind: "receipt", receipt: captured ? { ...request, output } : null, digest: captured ? "b".repeat(64) : null } };
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", process: { executionId: "command", generation: 1, interruption: stopped,
      report: { kind: "unavailable", lastKnown: { request, guestPid: 23, lineage: null, state } } } } };
  });
  const execution = new Execution(machine, "command", 1);
  assert.equal((await execution.waitLeader()).state.kind, "draining");
  await assert.rejects(execution.waitCapture(), ExecutionInterruptedError);
  state = { kind: "exited", output };
  await assert.rejects(execution.waitCapture(), ExecutionInterruptedError);
  captured = true;
  assert.equal((await execution.waitCapture()).state.kind, "exited");
});

test("restored execution reservations require reattachment rather than rebinding an old handle", async () => {
  const request = { machineId: "box", generation: 1, executionId: "command" };
  const machine = fixtureMachine(async (query) => {
    if (query.kind === "list-events") return eventPage(0, []);
    assert.equal(query.kind, "get-process");
    return { kind: "runtime", response: { kind: "process", request,
      process: { executionId: "command", generation: 2, interruption: null, report: { kind: "unavailable", lastKnown: null } } } };
  });
  await assert.rejects(new Execution(machine, "command", 1).waitLeader(), (error) => error instanceof SandsurfHostError && error.category === "stale-generation");
  assert.equal((await machine.executions.get("command")).generation, 2);
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
    return { kind: "runtime", response: { kind: "process", process: { executionId: "command", generation: 1,
      report: { kind: "unavailable", lastKnown: null }, interruption: stopped } } };
  });
  const execution = new Execution(machine, "command", 1);
  const stream = execution.output.follow();
  assert.deepEqual(Buffer.from((await stream.next()).value.bytes), bytes);
  await assert.rejects(stream.next(), ExecutionInterruptedError);
  assert.deepEqual(Buffer.from((await execution.output.read()).chunks[0].bytes), bytes);
});
