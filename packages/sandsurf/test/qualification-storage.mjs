import { realpath, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import { pathToFileURL, fileURLToPath } from "node:url";
import { isAbsolute, join } from "node:path";

// Hardware fixtures use operator-mounted volumes, not unbounded mkdtemp
// directories. They never mount, resize, recycle, or erase retained evidence.
export async function qualificationDirectory(name) {
  const root = process.env.SANDSURF_QUALIFICATION_ROOT;
  if (root === undefined || !isAbsolute(root)) throw new Error("provision bounded qualification volumes and set SANDSURF_QUALIFICATION_ROOT to their absolute parent");
  const path = join(root, name);
  if (await realpath(path) !== path) throw new Error("qualification storage must be canonical");
  return path;
}

// Record only after the caller's assertions succeed. These are test
// observations requiring operator acceptance, not another qualification owner.
export async function recordChecks(directory, machine, checks, facts) {
  const destination = process.env.SANDSURF_QUALIFICATION_EVIDENCE_DIRECTORY;
  if (destination === undefined) return;
  if (!isAbsolute(destination)) throw new Error("qualification evidence directory must be absolute");
  const packageRoot = process.env.SANDSURF_TEST_PACKAGE_ROOT ?? fileURLToPath(new URL("..", import.meta.url));
  const { resolveSandsurfNativeHost } = await import(pathToFileURL(join(packageRoot, "dist/native-host.js")));
  const { stdout } = await promisify(execFile)(await resolveSandsurfNativeHost(), ["qualification-config", "--directory", directory, "--machine", machine.id],
    { timeout: 10_000, maxBuffer: 64 * 1024 });
  const bytes = Buffer.from(`${JSON.stringify({ formatVersion: 1, configuration: JSON.parse(stdout), observedUnixMillis: Date.now(), checks, facts })}\n`);
  if (bytes.byteLength > 128 * 1024) throw new Error("qualification observation exceeds bound");
  const identity = createHash("sha256").update(bytes).digest("hex");
  await writeFile(join(destination, `check-${identity}.json`), bytes, { flag: "wx", mode: 0o600 });
}
