import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, readdir, rm, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { collectAlpineSources, publishAlpineSources, recipeChecksums, verifyAlpineSources } from "../alpine-sources.ts";

const origin = { origin: "example", buildCommit: "a".repeat(40) };
const digest = (bytes, algorithm = "sha256") => createHash(algorithm).update(bytes).digest("hex");
const blob = (bytes) => createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
function sourceFixtureTransport(recipe = Buffer.from('pkgname=example\nsource=""\n')) {
  const source = Buffer.from("verified upstream source bytes");
  const local = Buffer.from("local patch bytes");
  const recipes = { APKBUILD: recipe, "fix.patch": local, "example.post-install": Buffer.from("#!/bin/sh\nexit 0\n") };
  return { source, recipes, transport: async (url) => {
    if (url.startsWith("https://api.github.com/")) return (async function* () {
      yield Buffer.from(JSON.stringify(Object.entries(recipes).map(([name, bytes]) => ({
        type: "file", name, path: `main/${origin.origin}/${name}`, sha: blob(bytes), size: bytes.length,
      }))));
    })();
    const basename = new URL(url).pathname.split("/").at(-1);
    const bytes = url.startsWith("https://distfiles.alpinelinux.org/") ? source : recipes[basename];
    return bytes === undefined ? undefined : (async function* () { yield bytes; })();
  } };
}
test("checksum data is literal, finite and never evaluated as a host recipe", () => {
  const sum = "a".repeat(128);
  assert.deepEqual([...recipeChecksums(Buffer.from(`sha512sums="\n${sum}  upstream.tar.xz\n"\n`))], [["upstream.tar.xz", sum]]);
  assert.equal(recipeChecksums(Buffer.from("pkgname=generated-meta\n")).size, 0);
  assert.deepEqual([...recipeChecksums(Buffer.from(`sha512sums="${sum}  alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub"`))],
    [["alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub", sum]]);
  for (const value of [
    `sha512sums="$(touch /host/file)"`, `sha512sums="\`host-command\`"`,
    `sha512sums="${sum}  ../escape"`, `sha512sums="${sum}  /absolute"`,
    `sha512sums="${sum}  duplicate\n${sum}  duplicate"`,
    `sha512sums="${sum}  file"\nsha512sums+="more"`,
    `source="unverified.tar.xz"`, `source=""\nsource+=dynamic`,
  ]) assert.throws(() => recipeChecksums(Buffer.from(value)));
});
test("corresponding source retains recipe directory, upstream bytes and local patches under one verified inventory", async () => {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-source-test-"));
  try {
    const data = sourceFixtureTransport();
    const recipe = Buffer.from(`pkgname=example\nsha512sums="\n${digest(data.source, "sha512")}  upstream.tar.xz\n${digest(data.recipes["fix.patch"], "sha512")}  fix.patch\n"\n`);
    const fixture = sourceFixtureTransport(recipe);
    const input = join(root, "input"), output = join(root, "published");
    const identity = await collectAlpineSources(input, [origin, origin], fixture.transport);
    const files = await verifyAlpineSources(input, identity, [origin]);
    assert.equal(files.length, 5);
    const inventory = JSON.parse(await readFile(join(input, `${identity}.json`), "utf8"));
    assert.ok(inventory.origins[0].recipes["example.post-install"], "installation scripts are corresponding recipe material too");
    assert.equal(inventory.origins[0].sources["upstream.tar.xz"].sha512, digest(data.source, "sha512"));
    await publishAlpineSources(input, output, identity, [origin]);
    await publishAlpineSources(input, output, identity, [origin]);
    assert.deepEqual(await verifyAlpineSources(output, identity, [origin]), files.map((path) => path.replace(input, output)).sort());
    await assert.rejects(verifyAlpineSources(output, identity, [{ ...origin, buildCommit: "b".repeat(40) }]));
    await writeFile(join(output, "unexpected-user-data"), "preserve me");
    await assert.rejects(publishAlpineSources(input, output, identity, [origin]), /unowned/u);
    assert.equal(await readFile(join(output, "unexpected-user-data"), "utf8"), "preserve me");
    const part = inventory.origins[0].sources["upstream.tar.xz"].chunks[0].sha256;
    await rm(join(output, "objects", part));
    await assert.rejects(verifyAlpineSources(output, identity, [origin]));
  } finally { await rm(root, { recursive: true, force: true }); }
});
test("unavailable or wrong upstream source cannot publish an inventory of pointers", async () => {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-source-failure-"));
  try {
    const data = sourceFixtureTransport(Buffer.from(`sha512sums="${"a".repeat(128)}  upstream.tar.xz"\n`));
    await assert.rejects(collectAlpineSources(root, [origin], data.transport), /digest mismatch/u);
    assert.ok(!(await readdir(root)).some((name) => name.endsWith(".json")));
  } finally { await rm(root, { recursive: true, force: true }); }
});
test("large source streams retain exact bounded chunks and reject truncation or substitution", async () => {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-source-chunks-"));
  try {
    const bytes = Buffer.alloc(32 * 1024 * 1024 + 7, 0x5a);
    const fixture = sourceFixtureTransport(Buffer.from(`sha512sums="${digest(bytes, "sha512")}  large.tar.xz"\n`));
    const transport = async (url) => url.startsWith("https://distfiles.alpinelinux.org/")
      ? (async function* () { for (let i = 0; i < bytes.length; i += 65537) yield bytes.subarray(i, i + 65537); })()
      : fixture.transport(url);
    const identity = await collectAlpineSources(root, [origin], transport);
    const inventory = JSON.parse(await readFile(join(root, `${identity}.json`), "utf8"));
    const material = inventory.origins[0].sources["large.tar.xz"];
    assert.deepEqual(material.chunks.map((value) => value.bytes), [32 * 1024 * 1024, 7]);
    assert.equal(material.bytes, bytes.length);
    await verifyAlpineSources(root, identity, [origin]);
    const last = join(root, "objects", material.chunks[1].sha256);
    await chmod(last, 0o600);
    await truncate(last, 6);
    await assert.rejects(verifyAlpineSources(root, identity, [origin]), /missing or changed/u);
    await rm(last);
    await writeFile(last, bytes.subarray(-7));
    const outside = join(root, "outside");
    await writeFile(outside, bytes.subarray(-7));
    await rm(last);
    await symlink(outside, last);
    await assert.rejects(verifyAlpineSources(root, identity, [origin]), /missing or changed/u);
  } finally { await rm(root, { recursive: true, force: true }); }
});
test("an incomplete previous source bundle cannot be replaced as though it were absent", async () => {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-source-incomplete-"));
  try {
    const input = join(root, "input"), output = join(root, "output");
    const identity = await collectAlpineSources(input, [origin], sourceFixtureTransport().transport);
    await publishAlpineSources(input, output, identity, [origin]);
    const inventory = JSON.parse(await readFile(join(output, `${identity}.json`), "utf8"));
    const path = join(output, "objects", inventory.origins[0].recipes.APKBUILD.chunks[0].sha256);
    await rm(path);
    await assert.rejects(publishAlpineSources(input, output, identity, [origin]));
    assert.ok((await readdir(output)).includes(`${identity}.json`));
    await assert.rejects(readFile(path), { code: "ENOENT" });
  } finally { await rm(root, { recursive: true, force: true }); }
});
