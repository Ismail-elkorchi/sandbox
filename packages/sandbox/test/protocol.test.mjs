import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  FrameDecodeError,
  FrameDecoder,
  MAX_CONTROL_PAYLOAD,
  MessageType,
  decodeControl,
  encodeControlFrame,
} from "../dist/protocol.js";
import { RuntimeClient, RuntimeLocator } from "../dist/runtime.js";

test("framed protocol accepts partial headers and payloads", () => {
  const bytes = encodeControlFrame(MessageType.Hello, { protocolMajor: 1 });
  const decoder = new FrameDecoder();
  const frames = [];
  for (const byte of bytes) frames.push(...decoder.push(Buffer.from([byte])));
  decoder.finish();
  assert.equal(frames.length, 1);
  assert.deepEqual(decodeControl(frames[0]), { protocolMajor: 1 });
});

test("framed protocol rejects magic, reserved bits, types, and allocation-sized lies", () => {
  const valid = encodeControlFrame(MessageType.Hello, {});
  const badMagic = Buffer.from(valid);
  badMagic[0] = 0;
  assert.throws(() => new FrameDecoder().push(badMagic), FrameDecodeError);

  const reserved = Buffer.from(valid);
  reserved[6] = 1;
  assert.throws(() => new FrameDecoder().push(reserved), FrameDecodeError);

  const unknownFlags = Buffer.from(valid);
  unknownFlags[5] = 1;
  assert.throws(() => new FrameDecoder().push(unknownFlags), FrameDecodeError);

  const unknown = Buffer.from(valid);
  unknown[4] = 99;
  assert.throws(() => new FrameDecoder().push(unknown), FrameDecodeError);

  const oversized = Buffer.alloc(12);
  oversized.write("SBX1", 0, "ascii");
  oversized[4] = MessageType.Hello;
  oversized.writeUInt32BE(MAX_CONTROL_PAYLOAD + 1, 8);
  assert.throws(() => new FrameDecoder().push(oversized), FrameDecodeError);
});

test("framed protocol rejects truncated final data", () => {
  const decoder = new FrameDecoder();
  decoder.push(Buffer.from("SBX", "ascii"));
  assert.throws(() => decoder.finish(), FrameDecodeError);
});

for (const mode of ["output-before-start", "exit-before-start", "credit-before-start"]) {
  test(`runtime client rejects ${mode.replaceAll("-", " ")}`, async () => {
    const runtime = await fakeRuntime(mode);
    let client;
    try {
      client = await RuntimeClient.launch(new RuntimeLocator(runtime));
      await assert.rejects(client.probe());
    } finally {
      await client?.shutdown();
      await runtime.cleanup();
    }
  });
}

test("runtime client rejects duplicate response identifiers", async () => {
  const runtime = await fakeRuntime("duplicate-response");
  let client;
  try {
    client = await RuntimeClient.launch(new RuntimeLocator(runtime));
    await client.probe().catch(() => undefined);
    await new Promise((resolveTurn) => setImmediate(resolveTurn));
    await assert.rejects(client.probe());
  } finally {
    await client?.shutdown();
    await runtime.cleanup();
  }
});

for (const mode of ["output-after-exit", "credit-overflow"]) {
  test(`runtime client rejects ${mode.replaceAll("-", " ")}`, async () => {
    const runtime = await fakeRuntime(mode);
    let client;
    try {
      client = await RuntimeClient.launch(new RuntimeLocator(runtime));
      await client.request(MessageType.StartPreparedRun, MessageType.ProcessStarted, { id: "prepared" }).catch(() => undefined);
      await new Promise((resolveTurn) => setImmediate(resolveTurn));
      await assert.rejects(client.probe());
    } finally {
      await client?.shutdown();
      await runtime.cleanup();
    }
  });
}

test("runtime client rejects duplicate HELLO acknowledgement", async () => {
  const runtime = await fakeRuntime("duplicate-hello");
  let client;
  try {
    client = await RuntimeClient.launch(new RuntimeLocator(runtime)).catch(() => undefined);
    if (client !== undefined) {
      await new Promise((resolveTurn) => setImmediate(resolveTurn));
      await assert.rejects(client.probe());
    }
  } finally {
    await client?.shutdown();
    await runtime.cleanup();
  }
});

test("runtime shutdown fails an active process that never produced a final result", async () => {
  const runtime = await fakeRuntime("shutdown-active");
  let client;
  try {
    client = await RuntimeClient.launch(new RuntimeLocator(runtime));
    await client.request(MessageType.StartPreparedRun, MessageType.ProcessStarted, { id: "prepared" });
    const failed = new Promise((resolveFailure) => {
      client.attachProcess({
        output() {}, artifact() {}, exit() {}, event() {}, fail: resolveFailure,
      });
    });
    await client.shutdown();
    assert.ok(await failed instanceof Error);
  } finally {
    await client?.shutdown();
    await runtime.cleanup();
  }
});

async function fakeRuntime(mode) {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-fake-runtime-"));
  const runtimePath = join(directory, "runtime");
  const source = `#!${process.execPath}
const mode=${JSON.stringify(mode)};
let buffered=Buffer.alloc(0);
function frame(type,value,binary=false){const payload=binary?Buffer.from(value):Buffer.from(JSON.stringify(value));const header=Buffer.alloc(12);header.write('SBX1');header[4]=type;header.writeUInt32BE(payload.length,8);return Buffer.concat([header,payload]);}
function send(type,value,binary=false){process.stdout.write(frame(type,value,binary));}
process.stdin.on('data',(chunk)=>{buffered=Buffer.concat([buffered,chunk]);while(buffered.length>=12){const length=buffered.readUInt32BE(8);if(buffered.length<12+length)return;const type=buffered[4];const payload=buffered.subarray(12,12+length);buffered=buffered.subarray(12+length);const body=type===12?{}:JSON.parse(payload.toString());if(type===1){const ack=frame(101,{protocolMajor:1,protocolMinor:0});process.stdout.write(mode==='duplicate-hello'?Buffer.concat([ack,ack]):ack);}else if(type===2){if(mode==='output-before-start')send(108,Buffer.from('x'),true);else if(mode==='exit-before-start')send(111,{});else if(mode==='credit-before-start')send(14,{stream:'stdin',bytes:1});else if(mode==='duplicate-response'){const response=frame(102,{requestId:body.requestId,support:{protocol:{major:1,minor:0},packageVersion:'test',host:{platform:process.platform,architecture:process.arch},backends:[]}});process.stdout.write(Buffer.concat([response,response]));}}else if(type===4){const started=frame(107,{requestId:body.requestId,id:'target',identity:{kind:'opaque'}});if(mode==='output-after-exit')process.stdout.write(Buffer.concat([started,frame(111,{}),frame(108,Buffer.from('late'))]));else if(mode==='credit-overflow')process.stdout.write(Buffer.concat([started,frame(14,{stream:'stdin',bytes:16777216}),frame(14,{stream:'stdin',bytes:1})]));else if(mode==='shutdown-active')process.stdout.write(started);}else if(type===17){send(114,{requestId:body.requestId});process.exit(0);}}});
`;
  await writeFile(runtimePath, source, { mode: 0o700 });
  await chmod(runtimePath, 0o700);
  return {
    runtimePath,
    runtimeDigest: createHash("sha256").update(source).digest("hex"),
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}
