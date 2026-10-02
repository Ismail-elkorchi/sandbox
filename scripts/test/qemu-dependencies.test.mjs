import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { collectDependencySources, dependencySourceFiles, licenseExpression, pacmanDescription, verifyDependencySources } from "../qemu-dependencies.ts";

test("installed package fields remain exact and reject duplicate or oversized metadata", () => {
  const description = "%NAME%\nmingw-w64-ucrt-x86_64-glib2\n\n%BASE%\nmingw-w64-glib2\n\n%VERSION%\n1:2.90.0-1\n\n%LICENSE%\nLGPL-2.1-or-later\n";
  assert.deepEqual(pacmanDescription(description).get("VERSION"), ["1:2.90.0-1"]);
  for (const text of ["%NAME%\nx\n\n%NAME%\ny", "NAME\nx", "%NAME%\nx\0", "x".repeat(65537)]) assert.throws(() => pacmanDescription(text));
  assert.equal(licenseExpression({ all_of: ["LGPL-2.1-or-later", { any_of: ["MIT", "BSD-3-Clause"] }] }), "(LGPL-2.1-or-later AND (MIT OR BSD-3-Clause))");
  for (const value of [null, "UNKNOWN", "custom:foo", { any_of: ["MIT"] }, { all_of: ["MIT", "UNKNOWN"] }, { all_of: ["MIT", "ISC"], more: true }]) assert.throws(() => licenseExpression(value));
});

async function fixture(context, manager = "homebrew") {
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-library-source-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const materials = {}, directory = resolve(root, "qemu-dependencies/glib");
  await mkdir(directory, { recursive: true });
  const files = manager === "homebrew" ? ["formula.rb", "install-receipt.json", "glib.tar.xz"]
    : ["installed-package.txt", "glib.src.tar.zst", "glib.src.tar.zst.sig"];
  for (const name of files) {
    const bytes = Buffer.from(`source:${name}`); await writeFile(resolve(directory, name), bytes); materials[name] = digest(bytes);
  }
  const binary = manager === "homebrew" ? "lib/libglib.dylib" : "libglib.dll";
  const runtime = { [binary]: digest("packaged native library") };
  const manifest = { formatVersion: 1, components: [{ manager, name: "glib", version: "2.90.0-1", license: "LGPL-2.1-or-later",
    binaries: { [binary]: { inputSha256: digest("installed native library"), sha256: runtime[binary] } }, materials }] };
  const publish = () => writeFile(resolve(root, "qemu-dependencies.json"), JSON.stringify(manifest));
  await publish();
  return { root, runtime, manifest, publish, directory, binary };
}

for (const manager of ["homebrew", "msys2"]) {
  test(`complete ${manager} source binds installed and packaged library identities`, async (context) => {
    const f = await fixture(context, manager);
    assert.deepEqual(await verifyDependencySources(f.root, f.runtime), f.manifest);
    assert.equal(dependencySourceFiles(f.manifest).length, 4);
    assert.ok(dependencySourceFiles(f.manifest).includes("qemu-dependencies.json"));
  });
}

for (const [name, corrupt] of [
  ["missing archive bytes", (f) => rm(resolve(f.directory, "glib.tar.xz"))],
  ["modified source bytes", (f) => writeFile(resolve(f.directory, "formula.rb"), "changed source recipe")],
  ["undeclared source material", (f) => writeFile(resolve(f.directory, "extra.tar.gz"), "unindexed bytes")],
  ["unbound packaged library", (f) => { f.runtime[f.binary] = "e".repeat(64); }],
  ["reference-only source", async (f) => { delete f.manifest.components[0].materials["glib.tar.xz"]; await rm(resolve(f.directory, "glib.tar.xz")); await f.publish(); }],
  ["missing installed recipe", async (f) => { delete f.manifest.components[0].materials["formula.rb"]; await rm(resolve(f.directory, "formula.rb")); await f.publish(); }],
  ["unknown licenses", async (f) => { f.manifest.components[0].license = "UNKNOWN"; await f.publish(); }],
  ["duplicated binary ownership", async (f) => { f.manifest.components.push({ ...f.manifest.components[0], name: "second" }); await f.publish(); }],
  ["unrecorded library", (f) => { f.runtime['lib/second.dylib'] = "e".repeat(64); }],
  ["shared source-file identity", async (f) => { await link(resolve(f.directory, "formula.rb"), resolve(f.root, "alias")); }],
  ["material path traversal", async (f) => { f.manifest.components[0].materials['../escape.tar.gz'] = "e".repeat(64); await f.publish(); }],
  ["extra source component directory", (f) => mkdir(resolve(f.root, "qemu-dependencies/other"))],
]) {
  test(`source verification rejects ${name}`, async (context) => {
    const f = await fixture(context); await corrupt(f);
    await assert.rejects(verifyDependencySources(f.root, f.runtime));
  });
}

test("source verification rejects linked material directories", { skip: process.platform === "win32" }, async (context) => {
  const f = await fixture(context); const bytes = await readFile(resolve(f.directory, "glib.tar.xz"));
  await rm(resolve(f.directory, "glib.tar.xz")); await writeFile(resolve(f.root, "source"), bytes);
  await symlink(resolve(f.root, "source"), resolve(f.directory, "glib.tar.xz"));
  await assert.rejects(verifyDependencySources(f.root, f.runtime));
});

test("an empty loader closure has exactly an empty source inventory", async (context) => {
  const f = await fixture(context); f.manifest.components = []; await f.publish();
  await assert.rejects(verifyDependencySources(f.root, {}));
  await rm(resolve(f.root, "qemu-dependencies"), { recursive: true });
  assert.deepEqual(await verifyDependencySources(f.root, {}), { formatVersion: 1, components: [] });
});

for (const platform of ["darwin", "win32"]) {
  test(`${platform} collection selects installed recipes and ships actual source bytes`, async (context) => {
    const root = await mkdtemp(resolve(tmpdir(), "sandsurf-source-collector-"));
    context.after(() => rm(root, { recursive: true, force: true }));
    const original = Object.getOwnPropertyDescriptor(process, "platform");
    const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
    const output = resolve(root, "payload"), scratch = resolve(root, "scratch"), cellar = resolve(root, "Cellar");
    await mkdir(scratch); await mkdir(output); await mkdir(cellar);
    const binary = platform === "darwin" ? "lib/libglib.dylib" : "libglib.dll";
    const installed = resolve(cellar, "glib", "2.90.0", "lib", "libglib.dylib");
    await mkdir(resolve(cellar, "glib/2.90.0/lib"), { recursive: true });
    await writeFile(installed, "installed bytes");
    await mkdir(resolve(output, "lib")); await writeFile(resolve(output, binary), "relocated and signed bytes");
    await mkdir(resolve(cellar, "glib/2.90.0/.brew"));
    await writeFile(resolve(cellar, "glib/2.90.0/.brew/glib.rb"), "exact installed formula");
    await writeFile(resolve(cellar, "glib/2.90.0/INSTALL_RECEIPT.json"), JSON.stringify({ version: "2.90.0" }));
    const database = resolve(root, "database"), owner = "mingw-w64-ucrt-x86_64-glib2";
    await mkdir(resolve(database, "local", `${owner}-2.90.0-1`), { recursive: true });
    await writeFile(resolve(database, "local", `${owner}-2.90.0-1`, "desc"),
      `%NAME%\n${owner}\n\n%BASE%\nmingw-w64-glib2\n\n%VERSION%\n2.90.0-1\n\n%LICENSE%\nLGPL-2.1-or-later\n`);
    const calls = [];
    async function run(command, args, cwd, capture, environment) {
      calls.push({ command, args, cwd, capture, environment });
      if (command === "brew" && args[0] === "--cellar") return cellar;
      if (command === "brew" && args[0] === "info") {
        assert.equal(args.at(-1), resolve(cellar, "glib/2.90.0/.brew/glib.rb"));
        return JSON.stringify({ formulae: [{ name: "glib", revision: 0, versions: { stable: "2.90.0" },
          urls: { stable: { checksum: digest("complete source archive") } }, license: "LGPL-2.1-or-later" }] });
      }
      if (command === "brew" && args[0] === "fetch") {
        assert.deepEqual(args, ["fetch", "--build-from-source", "--formula", resolve(cellar, "glib/2.90.0/.brew/glib.rb")]);
        assert.equal(environment.HOMEBREW_NO_AUTO_UPDATE, "1");
        const downloads = resolve(environment.HOMEBREW_CACHE, "downloads"); await mkdir(downloads, { recursive: true });
        await writeFile(resolve(downloads, "glib.tar.xz"), "complete source archive");
        await writeFile(resolve(downloads, "fix.patch"), "verified formula patch"); return "";
      }
      if (command === "cygpath") return args[1];
      if (command === "pacman") return owner;
      if (command === "pacman-conf") return database;
      if (command === "curl") { await writeFile(args[args.indexOf("--output") + 1], "signed package source"); return ""; }
      if (command === "bash") {
        assert.equal(args[1], 'exec pacman-key --verify "$@"');
        assert.ok(args[3].endsWith("mingw-w64-glib2-2.90.0-1.src.tar.zst.sig"));
        assert.equal(args[4], args[3].slice(0, -4)); return "";
      }
      throw new Error(`unexpected native source command ${command}`);
    }
    Object.defineProperty(process, "platform", { value: platform, configurable: true });
    try {
      await collectDependencySources(output, new Map([[binary, { path: installed, sha256: digest("installed bytes") }]]), scratch, run);
      const manifest = await verifyDependencySources(output, { [binary]: digest("relocated and signed bytes") });
      assert.equal(manifest.components.length, 1);
      assert.deepEqual(manifest.components[0].binaries[binary], {
        inputSha256: digest("installed bytes"), sha256: digest("relocated and signed bytes") });
      if (platform === "win32") assert.ok(calls.some((call) => call.command === "bash"));
      else assert.equal(Object.keys(manifest.components[0].materials).length, 4);
    } finally { Object.defineProperty(process, "platform", original); }
  });
}
