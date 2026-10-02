import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const packageRoot = process.env.SANDSURF_TEST_PACKAGE_ROOT ?? fileURLToPath(new URL("..", import.meta.url));
const { main } = await import(pathToFileURL(join(packageRoot, "dist/cli.js")).href);

test("CLI rejects duplicated, irrelevant and incomplete options before touching a native host", async () => {
  for (const arguments_ of [
    ["unknown", "--directory", "/nonexistent"],
    ["qualify", "--directory", "/nonexistent"],
    ["inspect", "--directory", "/nonexistent", "--machine", "computer"],
    ["setup", "--directory", "/nonexistent", "--json", "--json"],
    ["qualification-requirements", "--directory", "/nonexistent", "--run", "missing"],
    ["qualification-accept", "--directory", "/nonexistent", "--operator", "operator"],
    ["qualification-config", "--directory", "/nonexistent"],
    ["storage-path", "--directory", "/nonexistent"],
    ["storage-volume", "--directory"],
  ]) await assert.rejects(main(arguments_), TypeError);
});
