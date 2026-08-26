import { spawn } from "node:child_process";

const allowed = new Set([
  "Apache-2.0",
  "MIT",
  "NCSA",
  "BSD-1-Clause",
  "BSD-3-Clause",
  "BSL-1.0",
  "Unicode-3.0",
  "Unlicense",
  "LLVM-exception",
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
  const normalized = expression.replaceAll("MIT/Apache-2.0", "MIT OR Apache-2.0");
  const tokens = normalized.match(/\(|\)|AND|OR|WITH|[A-Za-z][A-Za-z0-9.+-]*/gu) ?? [];
  if (tokens.join(" ").replaceAll("( ", "(").replaceAll(" )", ")") === "") return false;
  let index = 0;
  const factor = (): boolean => {
    if (tokens[index] === "(") {
      index += 1;
      const value = alternatives();
      if (tokens[index] !== ")") throw new Error(`invalid SPDX expression: ${expression}`);
      index += 1;
      return value;
    }
    const license = tokens[index++];
    if (license === undefined || ["AND", "OR", "WITH", ")"].includes(license)) {
      throw new Error(`invalid SPDX expression: ${expression}`);
    }
    let value = allowed.has(license);
    if (tokens[index] === "WITH") {
      index += 1;
      const exception = tokens[index++];
      value = value && exception !== undefined && allowed.has(exception);
    }
    return value;
  };
  const conjunction = (): boolean => {
    let value = factor();
    while (tokens[index] === "AND") {
      index += 1;
      const next = factor();
      value = value && next;
    }
    return value;
  };
  const alternatives = (): boolean => {
    let value = conjunction();
    while (tokens[index] === "OR") {
      index += 1;
      const next = conjunction();
      value = value || next;
    }
    return value;
  };
  const result = alternatives();
  if (index !== tokens.length) throw new Error(`invalid SPDX expression: ${expression}`);
  return result;
}

function capture(command: string, arguments_: readonly string[]): Promise<string> {
  return new Promise((resolveRun, rejectRun) => {
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    const child = spawn(command, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => errors.push(chunk));
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun(Buffer.concat(output).toString("utf8"));
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"}): ${Buffer.concat(errors).toString("utf8").slice(-4096)}`));
    });
  });
}
