import { spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const check = process.argv.slice(2);
if (check.length > 1 || (check.length === 1 && check[0] !== "--check")) throw new Error("usage: generate-protocol.ts [--check]");
const result = spawnSync("cargo", ["run", "--locked", "-p", "sandsurf-protocol", "--features", "typescript", "--bin", "sandsurf-protocol-typescript", "--", ...check], { encoding: "utf8", maxBuffer: 1024 * 1024 });
if (result.error !== undefined) throw result.error;
if (result.status !== 0) throw new Error(result.stderr);
if (check.length === 0) await writeFile(resolve("packages/sandsurf/src/protocol-generated.ts"), result.stdout);
