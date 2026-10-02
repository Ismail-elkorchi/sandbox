import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../build-qemu.ts";

const limits = { timeoutMs: 3000, maximumOutputBytes: 1024 };
test("bounded native build calls require successful exit and complete bounded stdout", async () => {
  assert.equal(await run(process.execPath, ["-e", 'process.stdout.write("complete output")'], process.cwd(), true, {}, limits), "complete output");
  await assert.rejects(run(process.execPath, ["-e", "process.exit(7)"], process.cwd(), true, {}, limits), /failed \(7\)/u);
  await assert.rejects(run(process.execPath, ["-e", 'process.stdout.write("x".repeat(1025))'], process.cwd(), true, {}, limits), /output bound/u);
  // Count bytes rather than UTF-16 characters, including across pipe chunks.
  await assert.rejects(run(process.execPath, ["-e", 'process.stdout.write("é".repeat(512)); setTimeout(() => process.stdout.write("x"), 100)'], process.cwd(), true, {}, limits), /output bound/u);
});
test("a wedged source verifier is terminated through its retained child", { timeout: 10000 }, async () => {
  const start = performance.now();
  await assert.rejects(run(process.execPath, ["-e", "setInterval(() => {}, 1000)"], process.cwd(), true, {},
    { timeoutMs: 250, maximumOutputBytes: 1024 }), /deadline/u);
  assert.ok(performance.now() - start < 5000);
});
test("invalid verifier limits and absent tools fail without an unbounded wait", async () => {
  for (const values of [{ ...limits, timeoutMs: 0 }, { ...limits, timeoutMs: 300001 },
    { ...limits, maximumOutputBytes: 0 }, { ...limits, maximumOutputBytes: 1048577 },
    { ...limits, maximumOutputBytes: 1.5 }]) {
    await assert.rejects(run(process.execPath, [], process.cwd(), true, {}, values), /invalid/u);
  }
  await assert.rejects(run(process.execPath, [], process.cwd(), false, {}, limits), /invalid/u);
  await assert.rejects(run("sandsurf-nonexistent-build-tool", [], process.cwd(), true, {}, limits), /ENOENT/u);
});
