import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, copyFile, link, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { collectDependencySources, dependencySourceFiles, downloadMsysSource, licenseExpression, msysLicenseExpression, msysSourceMirrors, pacmanDescription, requireDetachedSignature, requireTrustedSignature, verifyDependencySources, verifyMsysSource } from "../qemu-dependencies.ts";
import { run as runBuild, windowsLibraries } from "../build-qemu.ts";

const fingerprint = "A".repeat(40);
const trustedStatus = `[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED ${fingerprint} 0\n[GNUPG:] SIG_ID abcdef123 2026-10-02 1790937600\n[GNUPG:] GOODSIG ${fingerprint.slice(-16)} Distribution signer\n[GNUPG:] VALIDSIG ${fingerprint} 2026-10-02 1790937600 0 4 0 22 8 00 ${fingerprint}\n[GNUPG:] TRUST_FULLY 0 pgp\n`;

test("corresponding source mirrors come from bounded installed HTTPS repositories", () => {
  assert.deepEqual(msysSourceMirrors("https://first.invalid/mingw/ucrt64/\r\nhttps://second.invalid/pub/msys2/mingw/ucrt64/\r\n", "ucrt64"),
    ["https://first.invalid/mingw/sources/", "https://second.invalid/pub/msys2/mingw/sources/"]);
  for (const value of ["", "http://mirror.invalid/mingw/ucrt64/", "https://user@mirror.invalid/mingw/ucrt64/",
    "https://mirror.invalid/mingw/clang64/", "https://mirror.invalid/mingw/ucrt64/?x=y",
    "https://mirror.invalid/mingw/ucrt64/#x", "https://mirror.invalid/%2f/mingw/ucrt64/",
    "https://mirror.invalid/../mingw/ucrt64/", "https://mirror.invalid/mingw/$repo/",
    "https://mirror.invalid/mingw/ucrt64/\0", "https://mirror.invalid/mingw/ucrt64/\n".repeat(41)]) {
    assert.throws(() => msysSourceMirrors(value, "ucrt64"));
  }
});

test("mirror retries never combine a partial source with another mirror's signature", async (context) => {
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-source-mirror-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const source = resolve(root, "source.src.tar.zst"), signature = `${source}.sig`, addresses = [];
  await downloadMsysSource(source, signature, "source.src.tar.zst", ["https://first.invalid/", "https://second.invalid/"], root,
    async (command, args, _cwd, capture, environment, limits) => {
      assert.equal(command, "curl"); assert.equal(capture, true); assert.deepEqual(environment, {});
      assert.ok(limits.timeoutMs <= 125000); assert.equal(limits.maximumOutputBytes, 65536);
      const address = args.at(-1), destination = args[args.indexOf("--output") + 1]; addresses.push(address);
      if (address.startsWith("https://first.invalid/")) {
        await writeFile(destination, "partial"); throw new Error("mirror unavailable");
      }
      if (destination === source) await assert.rejects(readFile(signature), { code: "ENOENT" });
      await writeFile(destination, address.endsWith(".sig") ? "signature-second" : "source-second"); return "";
    });
  assert.deepEqual(addresses, ["https://first.invalid/source.src.tar.zst", "https://second.invalid/source.src.tar.zst", "https://second.invalid/source.src.tar.zst.sig"]);
  assert.equal(await readFile(source, "utf8"), "source-second");
  assert.equal(await readFile(signature, "utf8"), "signature-second");
});

test("source downloads satisfy the actual bounded native build runner contract", async (context) => {
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-source-runner-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const source = resolve(root, "source.src.tar.zst"), signature = `${source}.sig`;
  await downloadMsysSource(source, signature, "source.src.tar.zst", ["https://mirror.invalid/"], root,
    async (command, args, cwd, capture, environment, limits) => {
      assert.equal(command, "curl");
      // Exercise the production process runner without a network dependency.
      // Archive body goes to an opened output path, not captured stdout.
      const destination = args[args.indexOf("--output") + 1];
      return runBuild(process.execPath, ["--input-type=module", "-e",
        'import fs from "node:fs"; fs.writeFileSync(process.argv[1], "bounded download");', destination],
      cwd, capture, environment, limits);
    });
  assert.equal(await readFile(source, "utf8"), "bounded download");
  assert.equal(await readFile(signature, "utf8"), "bounded download");
});

test("detached signatures admit one bounded packet, never expandable OpenPGP messages", () => {
  for (const bytes of [[0x88, 1, 4], [0x89, 0, 1, 4], [0x8a, 0, 0, 0, 1, 4],
    [0xc2, 1, 4], [0xc2, 255, 0, 0, 0, 1, 4]]) requireDetachedSignature(Buffer.from(bytes));
  requireDetachedSignature(Buffer.concat([Buffer.from([0xc2, 192, 0]), Buffer.alloc(192)]));
  for (const bytes of [[], [0x88], [0x88, 0, 4], [0x89, 255, 255, 4], [0x8b, 4, 4],
    [0x8a, 0, 0, 0], [0x8a, 255, 255, 255, 255, 4], [0xc2, 255, 0], [0xc2, 224, 4],
    [0xc2, 192, 0, 4], [0xc8, 1, 4], [0xcb, 1, 4], [0xc2, 1, 4, 0xc2, 1, 4],
    [0x88, 1, 4, 0], Buffer.alloc(65537), Buffer.from("-----BEGIN PGP SIGNATURE-----")]) {
    assert.throws(() => requireDetachedSignature(Buffer.from(bytes)));
  }
});

test("source trust requires one complete valid signature, not a success substring", () => {
  requireTrustedSignature(trustedStatus);
  requireTrustedSignature(trustedStatus.replace("Distribution signer", "Léo — distribution signer"));
  requireTrustedSignature(trustedStatus.replace("TRUST_FULLY", "TRUST_ULTIMATE").replaceAll("\n", "\r\n"));
  for (const status of ["", trustedStatus.trimEnd(), "[GNUPG:] TRUST_FULLY 0 pgp\n", trustedStatus.repeat(2),
    trustedStatus.replace(/.*GOODSIG.*\n/u, ""), trustedStatus.replace(/.*VALIDSIG.*\n/u, ""),
    trustedStatus.replace(/.*TRUST_FULLY.*\n/u, ""), trustedStatus.replace("TRUST_FULLY", "TRUST_MARGINAL"),
    trustedStatus.replace("TRUST_FULLY", "TRUST_UNDEFINED"), trustedStatus.replace("0 pgp", "0 always"),
    trustedStatus.replace(`GOODSIG ${fingerprint.slice(-16)}`, `GOODSIG ${"B".repeat(16)}`),
    trustedStatus.replace("8 00", "8 01"), trustedStatus.replace("[GNUPG:]", "not [GNUPG:]"),
    trustedStatus + "[GNUPG:] BADSIG ABC bad\n", trustedStatus + "[GNUPG:] FAILURE verify 1\n",
    trustedStatus + "[GNUPG:] EXPKEYSIG ABC expired\n", trustedStatus + "[GNUPG:] REVKEYSIG ABC revoked\n",
    trustedStatus + "[GNUPG:] TRUST_NEVER 0 pgp\n", trustedStatus + "[GNUPG:] UNKNOWN\n",
    trustedStatus + "\0", trustedStatus + "\n", "x".repeat(65537),
    trustedStatus.replace("Distribution signer", "x".repeat(4096)),
    trustedStatus.replace("[GNUPG:] GOODSIG", `[GNUPG:] KEY_CONSIDERED ${fingerprint} 0\n`.repeat(65) + "[GNUPG:] GOODSIG")]) {
    assert.throws(() => requireTrustedSignature(status));
  }
});

test("source verifier binds the bytes checked and never elevates or updates trust", async (context) => {
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-signature-source-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const source = resolve(root, "source.tar.zst"), signature = `${source}.sig`;
  await writeFile(source, "source archive"); await writeFile(signature, Buffer.from([0x88, 1, 4]));
  async function run(command, args, _cwd, capture, environment, limits) {
    assert.equal(capture, true);
    if (command === "pacman-conf") { assert.deepEqual(args, ["GPGDir"]); return "/etc/pacman.d/gnupg"; }
    if (command === "cygpath") { assert.equal(args[0], "-u"); return args[1]; }
    assert.equal(command, "gpg");
    assert.deepEqual(environment, {});
    assert.deepEqual(limits, { timeoutMs: 30000, maximumOutputBytes: 65536 });
    assert.deepEqual(args, ["--no-options", "--homedir", "/etc/pacman.d/gnupg", "--batch", "--no-tty",
      "--no-autostart", "--lock-never", "--no-auto-check-trustdb", "--no-auto-key-retrieve",
      "--auto-key-locate", "clear", "--trust-model", "pgp", "--status-fd", "1", "--verify", signature, source]);
    return trustedStatus;
  }
  const result = await verifyMsysSource(source, signature, root, run);
  assert.equal(result.source, createHash("sha256").update("source archive").digest("hex"));
  await assert.rejects(verifyMsysSource(source, signature, root, async (...args) => {
    const status = await run(...args);
    if (args[0] === "gpg") await writeFile(source, "replaced archive");
    return status;
  }), /changed during verification/u);
  await writeFile(signature, "-----BEGIN PGP SIGNATURE-----");
  await assert.rejects(verifyMsysSource(source, signature, root, run), /binary detached/u);
});

test("real GPG verifies a read-only trusted keyring and rejects an untrusted signer and altered bytes",
  { skip: process.platform === "win32", timeout: 30000 }, async (context) => {
    const execute = promisify(execFile);
    try { await execute("gpg", ["--version"], { timeout: 5000, maxBuffer: 65536 }); }
    catch (error) { if (error.code === "ENOENT") { context.skip("GPG is not installed"); return; } throw error; }
    // GPG creates native Unix sockets below its homedir. Darwin's per-user
    // TMPDIR can exhaust sun_path before the agent has even started.
    const root = await realpath(await mkdtemp(resolve(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "ss-gpg-")));
    const keyring = resolve(root, "keyring"), untrusted = resolve(root, "untrusted");
    await mkdir(keyring, { mode: 0o700 }); await mkdir(untrusted, { mode: 0o700 });
    context.after(async () => {
      await chmod(keyring, 0o700);
      await execute("gpgconf", ["--homedir", keyring, "--kill", "gpg-agent"], { timeout: 5000 });
      await rm(root, { recursive: true, force: true });
    });
    const gpg = async (home, args) => (await execute("gpg", ["--no-options", "--homedir", home,
      "--batch", "--no-tty", ...args], { timeout: 15000, maxBuffer: 65536 })).stdout;
    await gpg(keyring, ["--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
      "Sandsurf isolated source test <source@example.invalid>", "ed25519", "sign", "0"]);
    await gpg(keyring, ["--check-trustdb"]);
    const source = resolve(root, "source.tar.zst"), signature = `${source}.sig`;
    await writeFile(source, "actual signed source bytes");
    await gpg(keyring, ["--pinentry-mode", "loopback", "--passphrase", "", "--output", signature, "--detach-sign", source]);
    const publicKey = resolve(root, "signer.gpg");
    await gpg(keyring, ["--output", publicKey, "--export"]);
    await gpg(untrusted, ["--import", publicKey]); await gpg(untrusted, ["--check-trustdb"]);
    // A user's config must not turn an unknown distribution signer into trust.
    await writeFile(resolve(untrusted, "gpg.conf"), "trust-model always\n");
    await execute("gpgconf", ["--homedir", keyring, "--kill", "gpg-agent"], { timeout: 5000 });
    const keyBytes = await readFile(resolve(keyring, "pubring.kbx"));
    const trustBytes = await readFile(resolve(keyring, "trustdb.gpg"));
    await chmod(resolve(keyring, "pubring.kbx"), 0o400); await chmod(resolve(keyring, "trustdb.gpg"), 0o400);
    await chmod(keyring, 0o500);
    const keyringFiles = await readdir(keyring);
    let selected = keyring;
    const run = async (command, args) => {
      if (command === "pacman-conf") return selected;
      if (command === "cygpath") return args[1];
      assert.equal(command, "gpg");
      return (await execute(command, args, { timeout: 10000, maxBuffer: 65536 })).stdout;
    };
    await verifyMsysSource(source, signature, root, run);
    assert.deepEqual(await readFile(resolve(keyring, "pubring.kbx")), keyBytes);
    assert.deepEqual(await readFile(resolve(keyring, "trustdb.gpg")), trustBytes);
    assert.deepEqual(await readdir(keyring), keyringFiles);
    selected = untrusted;
    await assert.rejects(verifyMsysSource(source, signature, root, run), /not trusted/u);
    selected = keyring; await writeFile(source, "altered source bytes");
    await assert.rejects(verifyMsysSource(source, signature, root, run));
  });

test("native MSYS2 installed library ships distribution-verified corresponding source",
  { skip: process.env.SANDSURF_MSYS_SOURCE_TEST !== "1", timeout: 300000 }, async (context) => {
    assert.equal(process.platform, "win32", "this is a native MSYS2 contract, not a simulated platform");
    const execute = promisify(execFile);
    const run = async (command, args, cwd, _capture, _environment, limits) => (await execute(command, args,
      { cwd, timeout: limits?.timeoutMs ?? 120000, maxBuffer: limits?.maximumOutputBytes ?? 1024 * 1024 })).stdout;
    const root = await mkdtemp(resolve(tmpdir(), "sandsurf-msys-source-contract-"));
    context.after(() => rm(root, { recursive: true, force: true }));
    const scratch = resolve(root, "scratch"), output = resolve(root, "output");
    await mkdir(scratch); await mkdir(output);
    assert.ok(process.env.MINGW_PREFIX, "the build must select an explicit MSYS2 toolchain");
    const prefix = (await run("cygpath", ["-w", `${process.env.MINGW_PREFIX}/bin`], scratch)).trim();
    const name = "libglib-2.0-0.dll", input = resolve(prefix, name);
    const digest = createHash("sha256").update(await readFile(input)).digest("hex");
    await copyFile(input, resolve(output, name));
    const libraries = await windowsLibraries(input, output);
    libraries.set(name, { path: input, sha256: digest });
    await collectDependencySources(output, libraries, scratch, run);
    const runtime = Object.fromEntries(await Promise.all([...libraries.keys()].map(async (file) =>
      [file, createHash("sha256").update(await readFile(resolve(output, file))).digest("hex")])));
    const manifest = await verifyDependencySources(output, runtime);
    assert.ok(manifest.components.length > 1, "the installed transitive DLL closure, not just GLib, must ship source");
    assert.ok(manifest.components.some((component) => component.name === "mingw-w64-glib2"));
    for (const component of manifest.components) {
      assert.equal(component.manager, "msys2");
      assert.ok(Object.keys(component.materials).some((file) => file.endsWith(".src.tar.zst")));
    }
  });

test("installed package fields remain exact and reject duplicate or oversized metadata", () => {
  const description = "%NAME%\nmingw-w64-ucrt-x86_64-glib2\n\n%BASE%\nmingw-w64-glib2\n\n%VERSION%\n1:2.90.0-1\n\n%LICENSE%\nLGPL-2.1-or-later\n";
  assert.deepEqual(pacmanDescription(description).get("VERSION"), ["1:2.90.0-1"]);
  for (const text of ["%NAME%\nx\n\n%NAME%\ny", "NAME\nx", "%NAME%\nx\0", "x".repeat(65537)]) assert.throws(() => pacmanDescription(text));
  assert.equal(licenseExpression({ all_of: ["LGPL-2.1-or-later", { any_of: ["MIT", "BSD-3-Clause"] }] }), "(LGPL-2.1-or-later AND (MIT OR BSD-3-Clause))");
  for (const value of [null, "UNKNOWN", "MIT OR UNKNOWN", "MIT OR LicenseRef-special", "MIT AND", "MIT .", "custom:foo", { any_of: ["MIT"] }, { all_of: ["MIT", "UNKNOWN"] }, { all_of: ["MIT", "ISC"], more: true }]) assert.throws(() => licenseExpression(value));
});

test("MSYS2 SPDX metadata preserves expressions and alternative licensing without legacy guesses", () => {
  assert.equal(msysLicenseExpression(["spdx:MIT AND BSD-3-Clause-Clear"]), "MIT AND BSD-3-Clause-Clear");
  assert.equal(msysLicenseExpression(["spdx:LGPL-2.1-only", "spdx:MPL-1.1"]), "((LGPL-2.1-only) OR (MPL-1.1))");
  assert.equal(msysLicenseExpression(["spdx:MIT OR BSD-2-Clause", "spdx:ISC AND Zlib"]), "((MIT OR BSD-2-Clause) OR (ISC AND Zlib))");
  assert.equal(msysLicenseExpression(["spdx:LGPL-2.1-or-later", "documentation:spdx:GPL-3.0-or-later"]),
    "((LGPL-2.1-or-later) AND (GPL-3.0-or-later))");
  assert.equal(msysLicenseExpression(["spdx:MIT", "spdx:BSD-2-Clause", "documentation:spdx:GFDL-1.3-or-later"]),
    "((((MIT) OR (BSD-2-Clause))) AND (GFDL-1.3-or-later))");
  for (const values of [[], ["MIT"], ["custom:MIT"], ["spdx:MIT", "BSD"], ["spdx:"], ["spdx:UNKNOWN"],
    ["documentation:spdx:MIT"], ["spdx:MIT", "documentation:spdx:UNKNOWN"], ["spdx:MIT", "documentation:GPL"],
    ["spdx:MIT", "examples:spdx:MIT"], Array(17).fill("spdx:MIT")]) {
    assert.throws(() => msysLicenseExpression(values));
  }
});

test("split binary packages retain every declaration and combine obligations while capturing one source archive", async (context) => {
  const original = Object.getOwnPropertyDescriptor(process, "platform");
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-msys-split-source-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const scratch = resolve(root, "scratch"), output = resolve(root, "output"), database = resolve(root, "db");
  await mkdir(scratch); await mkdir(output);
  const libraries = new Map(), runtime = {};
  const owners = new Map();
  for (const [name, license] of [["first", "spdx:LGPL-2.1-or-later"], ["second", "spdx:GPL-3.0-or-later"], ["third", "spdx:LGPL-2.1-or-later"]]) {
    const owner = `mingw-w64-ucrt-x86_64-${name}`, bin = `${name}.dll`, input = resolve(root, bin);
    const desc = resolve(database, "local", `${owner}-1.0-1`);
    await mkdir(desc, { recursive: true });
    await writeFile(resolve(desc, "desc"), `%NAME%\n${owner}\n\n%BASE%\nmingw-w64-shared\n\n%VERSION%\n1.0-1\n\n%LICENSE%\n${license}\n`);
    await writeFile(input, `bytes:${name}`); await copyFile(input, resolve(output, bin));
    const sha256 = createHash("sha256").update(`bytes:${name}`).digest("hex");
    libraries.set(bin, { path: input, sha256 }); runtime[bin] = sha256; owners.set(input, owner);
  }
  let downloads = 0;
  async function run(command, args) {
    if (command === "cygpath") return args[1];
    if (command === "pacman") return owners.get(args.at(-1));
    if (command === "pacman-conf") return args[0] === "DBPath" ? database
      : args[0] === "--repo" ? "https://mirror.example.invalid/mingw/ucrt64/" : "/distribution/keyring";
    if (command === "curl") {
      downloads++;
      const destination = args[args.indexOf("--output") + 1];
      await writeFile(destination, destination.endsWith(".sig") ? Buffer.from([0x88, 1, 4]) : "one corresponding source archive"); return "";
    }
    if (command === "gpg") return trustedStatus;
    throw new Error(`unexpected command ${command}`);
  }
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  try {
    await collectDependencySources(output, libraries, scratch, run);
    const manifest = await verifyDependencySources(output, runtime);
    assert.equal(manifest.components.length, 1);
    assert.equal(downloads, 2, "one source archive and its signature, not one copy per DLL");
    const component = manifest.components[0];
    assert.equal(component.license, "((GPL-3.0-or-later) AND (LGPL-2.1-or-later))");
    assert.equal(Object.keys(component.materials).filter((name) => name.startsWith("installed-package.")).length, 3);
    assert.equal(Object.keys(component.binaries).length, 3);
  } finally { Object.defineProperty(process, "platform", original); }
});

async function fixture(context, manager = "homebrew") {
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-library-source-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const materials = {}, directory = resolve(root, "qemu-dependencies/glib");
  await mkdir(directory, { recursive: true });
  const files = manager === "homebrew" ? ["formula.rb", "install-receipt.json", "glib.tar.xz"]
    : ["installed-package.mingw-w64-glib.txt", "glib.src.tar.zst", "glib.src.tar.zst.sig"];
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
    const root = await realpath(await mkdtemp(resolve(tmpdir(), "sandsurf-source-collector-")));
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
      `%NAME%\n${owner}\n\n%BASE%\nmingw-w64-glib2\n\n%VERSION%\n2.90.0-1\n\n%LICENSE%\nspdx:LGPL-2.1-or-later\n`);
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
      if (command === "pacman-conf") return args[0] === "DBPath" ? database
        : args[0] === "--repo" ? "https://mirror.example.invalid/mingw/ucrt64/" : "/etc/pacman.d/gnupg";
      if (command === "curl") {
        const destination = args[args.indexOf("--output") + 1];
        await writeFile(destination, destination.endsWith(".sig") ? Buffer.from([0x88, 1, 4]) : "signed package source"); return "";
      }
      if (command === "gpg") {
        assert.ok(args.at(-2).endsWith("mingw-w64-glib2-2.90.0-1.src.tar.zst.sig"));
        assert.equal(args.at(-1), args.at(-2).slice(0, -4)); return trustedStatus;
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
      if (platform === "win32") assert.ok(calls.some((call) => call.command === "gpg"));
      else assert.equal(Object.keys(manifest.components[0].materials).length, 4);
    } finally { Object.defineProperty(process, "platform", original); }
  });
}
