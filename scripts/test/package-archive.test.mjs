import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomFillSync } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { promisify } from "node:util";
import test from "node:test";
import { assertPayloadClosure, packageArchive } from "../package-archive.ts";

const exec = promisify(execFile);
const npmCli = process.env.npm_execpath;

test("packaged payloads exactly match their authoritative manifest closure", () => {
  const prefix = "package/images/";
  const expected = [prefix + "manifest.json", prefix + "development-x64/system.ext4.gz"];
  assert.doesNotThrow(() => assertPayloadClosure(["package/README.md", prefix, ...expected], prefix, expected));
  for (const extra of ["retired-disk.gz", "undeclared-kernel", "undeclared.json", "system.ext4"]) {
    assert.throws(() => assertPayloadClosure([...expected, prefix + extra], prefix, expected), /undeclared/u);
  }
  assert.throws(() => assertPayloadClosure(expected.slice(1), prefix, expected), /missing/u);
  assert.throws(() => assertPayloadClosure([...expected, expected[0]], prefix, expected), /duplicate/u);
  assert.throws(() => assertPayloadClosure(expected, prefix, [...expected, expected[0]]), /inventory/u);
  assert.throws(() => assertPayloadClosure(expected, prefix, ["package/native/foreign"]), /inventory/u);
});

async function fixture(context, manifest = {}) {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-archive-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source");
  const destination = join(root, "output");
  await mkdir(source);
  await writeFile(join(source, "package.json"), JSON.stringify({ name: "sandsurf", version: "1.0.0", files: ["payload"], ...manifest }));
  return { root, source, destination };
}

test("archive identity and hooks reject before packing or publishing", async (context) => {
  for (const manifest of [{ name: "../escape" }, { version: "../escape" }, { scripts: { prepare: "exit 1" } }]) {
    const f = await fixture(context, manifest);
    await assert.rejects(packageArchive(f.source, f.destination, "unused"), /invalid|forbidden/u);
    await assert.rejects(readdir(f.destination), { code: "ENOENT" });
  }
});

test("npm archive streams large incompressible payloads with bounded memory", { skip: npmCli === undefined ? "run through npm run test:scripts" : false, timeout: 60_000 }, async (context) => {
  const f = await fixture(context);
  await writeFile(join(f.source, "README.md"), "Sandsurf fixture");
  await writeFile(join(f.source, "not-published"), "excluded");
  await pipeline((async function* () {
    for (let index = 0; index < 512; index++) yield randomFillSync(Buffer.alloc(256 * 1024));
  })(), createWriteStream(join(f.source, "payload"), { flags: "wx" }));
  const module = new URL("../package-archive.ts", import.meta.url).href;
  const { stdout } = await exec(process.execPath, ["--max-old-space-size=64", "--input-type=module", "--eval", `
    import { packageArchive } from ${JSON.stringify(module)};
    const path = await packageArchive(${JSON.stringify(f.source)}, ${JSON.stringify(f.destination)}, ${JSON.stringify(npmCli)});
    console.log(JSON.stringify({ path, maxRSS: process.resourceUsage().maxRSS }));
  `], { maxBuffer: 4096 });
  const result = JSON.parse(stdout);
  assert.ok(result.maxRSS < 180 * 1024, `streaming pack used ${result.maxRSS} KiB RSS`);
  const { stdout: listing } = await exec("tar", ["-tzf", result.path], { maxBuffer: 4096 });
  assert.deepEqual(listing.trim().split(/\r?\n/u).sort(), ["package/README.md", "package/package.json", "package/payload"]);
  assert.deepEqual(await readdir(f.destination), ["sandsurf-1.0.0.tgz"]);
});

test("bounded archive writer preserves npm selection, bin modes and reproducible metadata", { skip: npmCli === undefined ? "run through npm run test:scripts" : false }, async (context) => {
  const f = await fixture(context, { bin: { sandsurf: "cli.mjs" } });
  await writeFile(join(f.source, "cli.mjs"), "#!/usr/bin/env node\nconsole.log('fixture');\n", { mode: 0o600 });
  await writeFile(join(f.source, "payload"), "payload bytes");
  await writeFile(join(f.source, "excluded"), "not published");
  const first = await packageArchive(f.source, f.destination, npmCli);
  const { stdout: listing } = await exec("tar", ["-tvzf", first], { maxBuffer: 4096 });
  assert.match(listing, /^-rwx.*package\/cli\.mjs$/mu);
  assert.doesNotMatch(listing, /excluded/u);
  const { stdout: payload } = await exec("tar", ["-xOzf", first, "package/payload"], { maxBuffer: 4096 });
  assert.equal(payload, "payload bytes");
  const second = await packageArchive(f.source, join(f.root, "second"), npmCli);
  const { readFile } = await import("node:fs/promises");
  assert.deepEqual(await readFile(first), await readFile(second));
});
