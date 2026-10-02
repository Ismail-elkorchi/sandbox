import { captureCommand as capture } from "./capture-command.ts";
import { evaluateLicense } from "./license-expression.ts";

const allowed = new Set([
  "Apache-2.0",
  "MIT",
  "NCSA",
  "0BSD",
  "BSD-1-Clause",
  "BSD-3-Clause",
  "BSL-1.0",
  "CDLA-Permissive-2.0",
  "ISC",
  "MIT-0",
  "Unicode-3.0",
  "Unlicense",
  "LLVM-exception",
  "Zlib",
]);

for (const manifest of ["Cargo.toml", "fuzz/Cargo.toml"]) {
  const metadata = JSON.parse(await capture("cargo", ["metadata", "--locked", "--format-version", "1", "--manifest-path", manifest]));
  if (!Array.isArray(metadata.packages)) throw new Error(`${manifest} returned invalid cargo metadata`);
  for (const package_ of metadata.packages) {
    if (typeof package_?.name !== "string" || typeof package_?.license !== "string") {
      throw new Error(`${manifest} contains a package without SPDX license metadata`);
    }
    if (!approvedExpression(package_.license)) {
      throw new Error(`${package_.name} has no approved license choice: ${package_.license}`);
    }
    if (package_.source !== null && package_.source !== undefined && !String(package_.source).startsWith("registry+https://github.com/rust-lang/crates.io-index")) {
      throw new Error(`${package_.name} uses an unapproved dependency source: ${package_.source}`);
    }
  }
}

function approvedExpression(expression: string): boolean {
  const normalized = expression
    .replaceAll("MIT/Apache-2.0", "MIT OR Apache-2.0")
    .replaceAll("Unlicense/MIT", "Unlicense OR MIT");
  return evaluateLicense(normalized, (id) => allowed.has(id), (id) => allowed.has(id));
}
