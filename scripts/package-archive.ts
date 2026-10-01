import { lstat, mkdir, mkdtemp, readFile, rename, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";

/** Use npm's package selection and tar writer, without libnpmpack's whole-archive Buffer. */
export async function packageArchive(directory: string, destination: string, npmCli: string): Promise<string> {
  const source = resolve(directory);
  const metadata = await lstat(resolve(source, "package.json"));
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 64 * 1024) {
    throw new Error("package manifest must be a bounded regular file");
  }
  const manifest: unknown = JSON.parse(await readFile(resolve(source, "package.json"), "utf8"));
  if (typeof manifest !== "object" || manifest === null || !("name" in manifest) ||
      typeof manifest.name !== "string" || !/^[a-z0-9][a-z0-9-]*$/u.test(manifest.name) ||
      !("version" in manifest) || typeof manifest.version !== "string" ||
      !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(manifest.version)) {
    throw new Error("package identity is invalid");
  }
  const scripts = "scripts" in manifest ? manifest.scripts : undefined;
  if (typeof scripts === "object" && scripts !== null &&
      ["prepare", "prepack", "postpack"].some((name) => name in scripts)) {
    throw new Error("package lifecycle hooks are forbidden; build artifacts explicitly before packing");
  }
  // npm_execpath selects the actual npm installation used by this build. Both
  // modules are that installation's own packaging implementation, not runtime dependencies.
  const npmRequire = createRequire(resolve(npmCli));
  const pacote = npmRequire("pacote") as {
    tarball: { file(source: string, destination: string, options: Record<string, unknown>): Promise<unknown> };
  };
  const Arborist: unknown = npmRequire("@npmcli/arborist");
  await mkdir(destination, { recursive: true });
  const stage = await mkdtemp(resolve(destination, ".package-"));
  const filename = `${manifest.name}-${manifest.version}.tgz`;
  const output = resolve(destination, filename);
  try {
    await pacote.tarball.file(source, resolve(stage, filename), { Arborist, ignoreScripts: true });
    await rename(resolve(stage, filename), output);
    return output;
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}
