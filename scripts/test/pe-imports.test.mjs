import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, open, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { peImports } from "../pe-imports.ts";

const exec = promisify(execFile);
const optional = 0x98, sections = optional + 240;
function fixture(normal = ["KERNEL32.dll", "libglib-2.0-0.dll"], delayed = ["kernel32.DLL", "libgio-2.0-0.dll"]) {
  const bytes = Buffer.alloc(0x800);
  bytes.writeUInt16LE(0x5a4d, 0); bytes.writeUInt32LE(0x80, 60);
  bytes.writeUInt32LE(0x4550, 0x80); bytes.writeUInt16LE(0x8664, 0x84);
  bytes.writeUInt16LE(2, 0x86); bytes.writeUInt16LE(240, 0x94);
  bytes.writeUInt16LE(0x20b, optional); bytes.writeUInt32LE(512, optional + 60);
  bytes.writeUInt32LE(16, optional + 108);
  bytes.writeUInt32LE(0x600, sections + 8); bytes.writeUInt32LE(0x1000, sections + 12);
  bytes.writeUInt32LE(0x600, sections + 16); bytes.writeUInt32LE(512, sections + 20);
  let name = 0x400;
  for (const [directory, start, stride, names] of [[1, 0x200, 20, normal], [13, 0x280, 32, delayed]]) {
    if (names.length === 0) continue;
    bytes.writeUInt32LE(0x1000 + start - 512, optional + 112 + directory * 8);
    bytes.writeUInt32LE((names.length + 1) * stride, optional + 116 + directory * 8);
    for (const [index, value] of names.entries()) {
      const entry = start + index * stride;
      if (directory === 13) bytes.writeUInt32LE(1, entry);
      bytes.writeUInt32LE(0x1000 + name - 512, entry + (directory === 1 ? 12 : 4));
      bytes.writeUInt32LE(0x1400, entry + (directory === 1 ? 16 : 12));
      name += bytes.write(value, name, "ascii") + 1;
    }
  }
  return bytes;
}
async function root(context) {
  const directory = await mkdtemp(join(tmpdir(), "sandsurf-pe-imports-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("native PE inventory reads normal and delay-load imports with one case-insensitive identity", async (context) => {
  const directory = await root(context), path = join(directory, "program.exe");
  await writeFile(path, fixture());
  assert.deepEqual(await peImports(path), ["KERNEL32.dll", "libglib-2.0-0.dll", "libgio-2.0-0.dll"]);
  await writeFile(path, fixture([], []));
  assert.deepEqual(await peImports(path), []);
});

test("large PE exception/debug tables do not become captured text or heap allocations", async (context) => {
  const directory = await root(context), path = join(directory, "debug.exe");
  const bytes = fixture();
  bytes.writeUInt32LE(128 * 1024 ** 2, sections + 40 + 8);
  bytes.writeUInt32LE(0x2000, sections + 40 + 12);
  bytes.writeUInt32LE(128 * 1024 ** 2, sections + 40 + 16);
  bytes.writeUInt32LE(0x800, sections + 40 + 20);
  bytes.writeUInt32LE(0x2000, optional + 112 + 3 * 8);
  bytes.writeUInt32LE(128 * 1024 ** 2, optional + 116 + 3 * 8);
  await writeFile(path, bytes);
  const file = await open(path, "r+");
  try {
    await file.truncate(128 * 1024 ** 2 + 0x800);
    await file.write(Buffer.from("DLL Name: unrelated-debug-text.dll"), 0, 34, 0x800);
  } finally { await file.close(); }
  const module = new URL("../pe-imports.ts", import.meta.url).href;
  const { stdout } = await exec(process.execPath, ["--max-old-space-size=32", "--input-type=module", "--eval", `
    import { peImports } from ${JSON.stringify(module)};
    console.log(JSON.stringify({ names: await peImports(${JSON.stringify(path)}), rss: process.resourceUsage().maxRSS }));
  `], { maxBuffer: 4096 });
  const result = JSON.parse(stdout);
  assert.deepEqual(result.names, ["KERNEL32.dll", "libglib-2.0-0.dll", "libgio-2.0-0.dll"]);
  // Node/libuv normalize maxRSS to KiB on every supported platform.
  assert.ok(result.rss < 128 * 1024, `PE inventory used ${result.rss} KiB RSS`);
});

for (const [name, corrupt] of [
  ["DOS signature", (b) => b.writeUInt16LE(0, 0)],
  ["PE header offset", (b) => b.writeUInt32LE(65537, 60)],
  ["PE signature", (b) => b.writeUInt32LE(0, 0x80)],
  ["other machine architecture", (b) => b.writeUInt16LE(0x14c, 0x84)],
  ["PE32 compatibility format", (b) => b.writeUInt16LE(0x10b, optional)],
  ["too many sections", (b) => b.writeUInt16LE(97, 0x86)],
  ["truncated optional header", (b) => b.writeUInt16LE(127, 0x94)],
  ["directory count", (b) => b.writeUInt32LE(17, optional + 108)],
  ["headers overlapping sections", (b) => b.writeUInt32LE(0x1100, optional + 60)],
  ["raw section outside file", (b) => b.writeUInt32LE(0xffffffff, sections + 16)],
  ["overlapping virtual sections", (b) => { b.writeUInt32LE(1, sections + 40 + 8); b.writeUInt32LE(0x1000, sections + 40 + 12); }],
  ["overlapping raw sections", (b) => {
    b.writeUInt32LE(1, sections + 40 + 8); b.writeUInt32LE(0x2000, sections + 40 + 12);
    b.writeUInt32LE(1, sections + 40 + 16); b.writeUInt32LE(512, sections + 40 + 20);
  }],
  ["short directory extent", (b) => b.writeUInt32LE(19, optional + 116 + 8)],
  ["missing terminator", (b) => b.writeUInt32LE(40, optional + 116 + 8)],
  ["uninitialized import directory", (b) => b.writeUInt32LE(0x1600, optional + 112 + 8)],
  ["missing DLL name", (b) => b.writeUInt32LE(0, 0x200 + 12)],
  ["name outside initialized bytes", (b) => b.writeUInt32LE(0x1600, 0x200 + 12)],
  ["missing import address table", (b) => b.writeUInt32LE(0, 0x200 + 16)],
  ["host path in DLL name", (b) => b.write("../escape.dll\0", 0x400)],
  ["non-ASCII DLL name", (b) => b.writeUInt8(0xcb, 0x400)],
  ["oversized DLL name", (b) => b.fill(0x61, 0x400, 0x400 + 129)],
  ["pointer-based delayed imports", (b) => b.writeUInt32LE(0, 0x280)],
  ["reserved delayed flags", (b) => b.writeUInt32LE(3, 0x280)],
]) {
  test(`PE dependency inventory rejects ${name}`, async (context) => {
    const directory = await root(context), path = join(directory, "invalid.exe");
    const bytes = fixture(); corrupt(bytes); await writeFile(path, bytes);
    await assert.rejects(peImports(path), /invalid or unbounded/u);
  });
}

test("PE readers reject aliases and oversized inputs before reading their bodies", { skip: process.platform === "win32" }, async (context) => {
  const directory = await root(context), path = join(directory, "program.exe"), alias = join(directory, "alias.exe");
  await writeFile(path, fixture()); await symlink(path, alias);
  await assert.rejects(peImports(alias), /invalid or unbounded/u);
  const file = await open(path, "r+");
  try { await file.truncate(512 * 1024 ** 2 + 1); } finally { await file.close(); }
  await assert.rejects(peImports(path), /invalid or unbounded/u);
});

test("the reader inventories the running native Windows Node PE", { skip: process.platform !== "win32" }, async () => {
  const names = await peImports(process.execPath);
  assert.ok(names.length > 0 && names.length <= 128);
  assert.ok(names.every((name) => name.toLowerCase().endsWith(".dll")));
});
