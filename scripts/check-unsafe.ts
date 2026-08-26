import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../crates");
const failures: string[] = [];

for (const path of await rustFiles(root)) {
  const lines = (await readFile(path, "utf8")).split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    if (!/\bunsafe\s+(?:\{|fn\b|extern\b)/u.test(lines[index] ?? "")) continue;
    const context = lines.slice(Math.max(0, index - 4), index).join("\n");
    if (!context.includes("SAFETY:")) {
      failures.push(`${path}:${index + 1}`);
    }
  }
}

if (failures.length !== 0) {
  throw new Error(`unsafe Rust without a local SAFETY comment:\n${failures.join("\n")}`);
}

async function rustFiles(directory: string): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) result.push(...await rustFiles(path));
    else if (entry.isFile() && entry.name.endsWith(".rs")) result.push(path);
  }
  return result.sort();
}
