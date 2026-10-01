import assert from "node:assert/strict";
import { test } from "node:test";
import { Machine, NativeConsole, Sandsurf, SandsurfHostError } from "../dist/index.js";

function computer(request) {
  // Native console routes require neither a management report nor guest APIs.
  const host = new Sandsurf({ request }, () => { throw new Error("console requested authority change"); });
  return new Machine(host, { id: "computer", configurationRevision: 1,
    machine: { kind: "current", value: { generation: 1, state: "running" } },
    management: { kind: "unavailable", lastKnown: null },
    executionDefaults: { environment: {}, workingDirectory: "/", user: "root" } });
}

test("native console preserves binary bytes and exposes retention loss without guest management", async () => {
  const requests = [];
  const machine = computer(async (request) => {
    requests.push(request);
    assert.equal(request.kind, "read-console");
    const retained = Buffer.from([0, 255, 128]);
    const bytes = retained.subarray(request.after, request.after + request.maximum);
    const end = request.after + bytes.byteLength;
    const loss = end >= retained.byteLength && end < 10 ? { from: end, to: 10 } : null;
    return { kind: "runtime", response: { kind: "console", page: { generation: request.generation,
      after: request.after, cursor: loss?.to ?? end, available: 10, bytes, loss, open: false, captureFailed: false } } };
  });
  const console = await machine.console.attach({ generation: 1 });
  assert.ok(console instanceof NativeConsole);
  const page = await console.read();
  assert.deepEqual([...page.bytes], [0, 255, 128]);
  assert.deepEqual(page.loss, { from: 3, to: 10 });
  assert.equal(page.cursor, 10);
  assert.equal(requests.every((request) => request.generation === 1), true);
  console.detach();
  await assert.rejects(console.read(), (error) => error.category === "detached");
  assert.equal(requests.length, 2, "detach does not issue native stop or close capture");
});

test("console input accepts only a prefix and never retries uncertain or stale delivery", async () => {
  let writes = 0;
  const machine = computer(async (request) => {
    assert.equal(request.kind, "write-console");
    assert.equal(request.generation, 1);
    writes += 1;
    if (writes === 1) return { kind: "runtime", response: { kind: "console-input", accepted: 1 } };
    throw new SandsurfHostError(writes === 2 ? "ambiguous" : "stale-generation", "native input unavailable");
  });
  const console = new NativeConsole(machine, 1);
  assert.equal(await console.write(Uint8Array.of(0, 255)), 1);
  await assert.rejects(console.write(Uint8Array.of(1)), (error) => error.category === "ambiguous");
  await assert.rejects(console.write(Uint8Array.of(1)), (error) => error.category === "stale-generation");
  assert.equal(writes, 3);
  await assert.rejects(console.write(new Uint8Array(4097)), RangeError);
  assert.equal(writes, 3);
});

test("native console rejects gaps that are not explicitly covered by loss", async () => {
  const machine = computer(async () => ({ kind: "runtime", response: { kind: "console", page: {
    generation: 1, after: 0, cursor: 10, available: 10, bytes: Uint8Array.of(0),
    loss: null, open: false, captureFailed: false,
  } } }));
  await assert.rejects(new NativeConsole(machine, 1).read(), (error) => error.category === "protocol");
});
