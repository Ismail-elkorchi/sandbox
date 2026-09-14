import assert from "node:assert/strict";
import { appendFile, mkdtemp, open, readFile, rm, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { appendOutput, ExecutionOutputReader } from "../dist/execution-output.js";
import { digestRun, ZERO_HASH } from "../dist/execution-record.js";

async function log(t) {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-output-reader-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, "output.jsonl"), "");
  const reader = new ExecutionOutputReader();
  let sequence = 0;
  const boundary = { finalCursor: 0, outputHash: ZERO_HASH, stdoutBytes: 0, stderrBytes: 0 };
  const append = async (stream, data) => {
    const bytes = Buffer.from(data);
    const chunk = { sequence: ++sequence, cursorStart: boundary.finalCursor, cursorEnd: boundary.finalCursor + bytes.length,
      stream, dataBase64: bytes.toString("base64"), previousHash: boundary.outputHash };
    boundary.outputHash = await appendOutput(directory, chunk);
    boundary.finalCursor = chunk.cursorEnd;
    boundary[stream + "Bytes"] += bytes.length;
    return chunk;
  };
  return { directory, reader, boundary, append };
}
const data = (page) => Buffer.concat(page.chunks.map((chunk) => chunk.data));

test("range pages preserve mixed stream identity and UTF-8 bytes split across chunks", async (t) => {
  const { directory, reader, boundary, append } = await log(t);
  await append("stdout", Buffer.from([0xf0, 0x9f]));
  await append("stderr", "err");
  await append("stdout", Buffer.from([0x98, 0x80]));
  const original = Buffer.from([0xf0, 0x9f, 0x65, 0x72, 0x72, 0x98, 0x80]);
  const delivered = []; let cursor = 0;
  while (cursor < boundary.finalCursor) {
    const page = await reader.read(directory, cursor, 1, 1024, boundary);
    assert.equal(page.cursorStart, cursor);
    assert.equal(page.cursorEnd, cursor + 1);
    assert.equal(page.availableCursorEnd, 7);
    delivered.push(data(page)); cursor = page.cursorEnd;
  }
  assert.deepEqual(Buffer.concat(delivered), original);
  const middle = await reader.read(directory, 1, 5, 1024, boundary);
  assert.deepEqual(middle.chunks.map((chunk) => chunk.stream), ["stdout", "stderr", "stdout"]);
  const final = await reader.read(directory, 7, 10, 1024, boundary);
  assert.equal(final.cursorEnd, 7); assert.deepEqual(final.chunks, []);
  await assert.rejects(reader.read(directory, 8, 1, 1024, boundary), /Invalid.*cursor/);
  assert.equal(reader.metrics.rebuilds, 1);
});

test("cold verification is measured once; warm pages and growth read bounded ranges", async (t) => {
  const { directory, reader, boundary, append } = await log(t);
  for (let index = 0; index < 256; index++) await append(index % 2 ? "stdout" : "stderr", Buffer.alloc(16 * 1024, index));
  const first = await reader.read(directory, 2 * 1024 * 1024 + 7, 1, 8 * 1024 * 1024);
  assert.equal(first.cursorEnd, 2 * 1024 * 1024 + 8);
  const coldBytes = reader.metrics.bytesRead;
  assert.ok(coldBytes > 4 * 1024 * 1024);
  for (let index = 0; index < 5; index++) {
    const before = reader.metrics.bytesRead;
    const page = await reader.read(directory, first.cursorEnd + index, 1, 8 * 1024 * 1024);
    assert.equal(data(page).length, 1);
    assert.ok(reader.metrics.bytesRead - before < 160 * 1024, JSON.stringify(reader.metrics));
  }
  const before = reader.metrics.bytesRead;
  const previousEnd = boundary.finalCursor;
  await append("stdout", "tail");
  assert.equal(data(await reader.read(directory, previousEnd, 10, 8 * 1024 * 1024, boundary)).toString(), "tail");
  assert.ok(reader.metrics.bytesRead - before < 160 * 1024);
  assert.equal(reader.metrics.rebuilds, 1);
  const restarted = new ExecutionOutputReader();
  assert.equal(data(await restarted.read(directory, previousEnd, 10, 8 * 1024 * 1024, boundary)).toString(), "tail");
  assert.equal(restarted.metrics.rebuilds, 1);
});

test("partial live append never advances the delivered or available cursor", async (t) => {
  const { directory, reader, boundary, append } = await log(t);
  await append("stdout", "first");
  const file = join(directory, "output.jsonl");
  const pending = { sequence: 2, cursorStart: 5, cursorEnd: 9, stream: "stderr", dataBase64: Buffer.from("last").toString("base64"), previousHash: boundary.outputHash };
  const line = JSON.stringify({ ...pending, hash: digestRun(pending).slice(7) }) + "\n";
  await appendFile(file, line.slice(0, 30));
  const partial = await reader.read(directory, 5, 10, 1024);
  assert.equal(partial.cursorEnd, 5); assert.equal(partial.availableCursorEnd, 5);
  await assert.rejects(reader.read(directory, 5, 10, 1024, boundary), /terminal receipt/);
  await appendFile(file, line.slice(30));
  const complete = await reader.read(directory, 5, 10, 1024);
  assert.equal(data(complete).toString(), "last"); assert.equal(complete.cursorEnd, 9);
});

test("truncation, recomputed prefix hashes and changed final boundaries fail verification", async (t) => {
  const { directory, reader, boundary, append } = await log(t);
  await append("stdout", "first"); await append("stderr", "last");
  const file = join(directory, "output.jsonl");
  const original = await readFile(file);
  await reader.read(directory, 0, 1, 1024, boundary);
  await truncate(file, original.length - 1);
  await assert.rejects(reader.read(directory, 0, 1, 1024, boundary), /terminal receipt/);
  await writeFile(file, original);
  await reader.read(directory, 0, 1, 1024, boundary);
  const lines = original.toString().trim().split("\n").map(JSON.parse);
  lines[0].dataBase64 = Buffer.from("other").toString("base64");
  const { hash, ...unsigned } = lines[0]; lines[0].hash = digestRun(unsigned).slice(7);
  await writeFile(file, lines.map(JSON.stringify).join("\n") + "\n");
  await assert.rejects(reader.read(directory, 0, 1, 1024, boundary), /hash chain/);
  await writeFile(file, original);
  await assert.rejects(reader.read(directory, 0, 1, 1024, { ...boundary, outputHash: "f".repeat(64) }), /terminal receipt/);
});

test("simultaneous polls serialize cache updates while append continues", async (t) => {
  const { directory, reader, boundary, append } = await log(t);
  await append("stdout", "old");
  const polls = Array.from({ length: 20 }, () => reader.read(directory, 0, 1, 1024));
  await append("stderr", "new");
  assert.ok((await Promise.all(polls)).every((page) => data(page).toString() === "o"));
  assert.equal(data(await reader.read(directory, 3, 10, 1024, boundary)).toString(), "new");
  assert.equal(reader.metrics.rebuilds, 1);
});
