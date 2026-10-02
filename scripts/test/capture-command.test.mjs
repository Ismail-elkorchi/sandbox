import assert from "node:assert/strict";
import test from "node:test";
import { captureCommand } from "../capture-command.ts";

test("metadata capture drains complete pipe bytes after producer exit", async () => {
  const bytes = 2 * 1024 ** 2;
  const output = await captureCommand(process.execPath, ["-e",
    `const {writeSync}=require('node:fs'); const b=Buffer.alloc(8192,0x78); for(let i=0;i<${bytes / 8192};i++)writeSync(1,b);`]);
  assert.equal(output.length, bytes);
  assert.equal(output, "x".repeat(bytes));
});
test("metadata capture rejects truncated encodings, excess bytes and failing producers", async () => {
  await assert.rejects(captureCommand(process.execPath, ["-e", "require('node:fs').writeSync(1,Buffer.from([0xff]));"]), /UTF-8/u);
  await assert.rejects(captureCommand(process.execPath, ["-e", "require('node:fs').writeSync(1,Buffer.alloc(4096));"], 1024), /byte bound/u);
  await assert.rejects(captureCommand(process.execPath, ["-e", "process.stderr.write('retained diagnostic');process.exitCode=7;"]), /retained diagnostic/u);
});
test("missing and wedged producers complete with failure instead of hanging", async () => {
  await assert.rejects(captureCommand("sandsurf-no-such-build-command", []));
  await assert.rejects(captureCommand(process.execPath, ["-e", "setInterval(()=>{},1000);"], 1024, 100), /deadline/u);
  for (const limit of [0, 0.5, 16 * 1024 ** 2 + 1]) assert.throws(() => captureCommand(process.execPath, [], limit));
});
