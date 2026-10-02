import assert from "node:assert/strict";
import test from "node:test";
import { evaluateLicense } from "../license-expression.ts";

const accepted = (expression) => evaluateLicense(expression, (id) => id === "MIT" || id === "Apache-2.0", (id) => id === "LLVM-exception");
test("one bounded grammar preserves precedence, grouping and exception ownership", () => {
  for (const value of ["MIT", "Apache-2.0", "GPL-2.0-only OR MIT", "MIT OR GPL-2.0-only AND Apache-2.0",
    "MIT WITH LLVM-exception", "(MIT AND Apache-2.0) OR GPL-2.0-only"]) assert.equal(accepted(value), true, value);
  for (const value of ["GPL-2.0-only", "MIT AND GPL-2.0-only", "(MIT OR GPL-2.0-only) AND GPL-2.0-only",
    "MIT WITH unknown-exception", "GPL-2.0-only WITH LLVM-exception"]) assert.equal(accepted(value), false, value);
  assert.equal(evaluateLicense("GPL-2.0-or-later WITH cryptsetup-OpenSSL-exception", () => true, () => true), true);
});
test("the entire expression is validated even when policy evaluation could short-circuit", () => {
  for (const value of ["", "MIT OR", "MIT AND", "GPL-2.0-only AND", "MIT OR (", "MIT MIT", "MIT:GPL-2.0",
    "MIT/Apache-2.0", "MIT_foo", "MIT\nOR Apache-2.0", "MIT\0", "MIT;GPL", "AND MIT", "WITH MIT", "()",
    ". MIT", "MIT +", "MIT++", "MIT WITH LLVM-exception+",
    "(MIT", "MIT)", "(MIT) WITH LLVM-exception", "MIT WITH (LLVM-exception)", "MIT WITH WITH",
    "MIT WITH LLVM-exception WITH LLVM-exception", "MIT OR OR MIT", "".padEnd(4097, "x"),
    `${"(".repeat(9)}MIT${")".repeat(9)}`, Array(130).fill("MIT").join(" OR ")]) {
    assert.throws(() => accepted(value), undefined, value);
  }
});
