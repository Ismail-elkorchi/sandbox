/** One bounded SPDX expression grammar for native metadata and Cargo policy.
 * Parsing establishes syntax, not a grant to redistribute software. Callers
 * decide which license/exception identifiers their distribution accepts. */
export function evaluateLicense(expression: string, license: (id: string) => boolean,
  exception: (id: string) => boolean): boolean {
  if (expression.length === 0 || expression.length > 4096 || !/^[A-Za-z0-9().+ -]+$/u.test(expression)) {
    throw new Error("invalid or oversized SPDX license expression");
  }
  const tokens: string[] = [];
  const token = /\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*| +/gy;
  while (token.lastIndex < expression.length) {
    const match = token.exec(expression);
    if (match === null) throw new Error("SPDX contains an invalid token");
    if (match[0][0] !== " ") tokens.push(match[0]);
    if (tokens.length > 256) throw new Error("SPDX token count exceeds its bound");
  }
  if (tokens.length === 0 || tokens.length > 256) throw new Error("SPDX token count exceeds its bound");
  let index = 0;
  const identifier = (): string => {
    const token = tokens[index++];
    if (token === undefined || ["(", ")", "AND", "OR", "WITH"].includes(token)
      || !/^[A-Za-z0-9][A-Za-z0-9.-]*\+?$/u.test(token)) {
      throw new Error("SPDX requires a license or exception identifier");
    }
    return token;
  };
  const factor = (depth: number): boolean => {
    if (depth > 8) throw new Error("SPDX expression nesting exceeds its bound");
    if (tokens[index] === "(") {
      index++;
      const accepted = alternatives(depth + 1);
      if (tokens[index++] !== ")") throw new Error("SPDX parenthesis is unmatched");
      return accepted;
    }
    let accepted = license(identifier());
    if (tokens[index] === "WITH") {
      index++;
      const id = identifier();
      if (id.endsWith("+")) throw new Error("SPDX exceptions cannot use a license suffix");
      const acceptedException = exception(id);
      accepted = accepted && acceptedException;
    }
    return accepted;
  };
  const conjunction = (depth: number): boolean => {
    let accepted = factor(depth);
    while (tokens[index] === "AND") {
      index++;
      // Always parse the next term, even after a denied license. Evaluation
      // must not short-circuit validation of the remaining metadata.
      const next = factor(depth);
      accepted = accepted && next;
    }
    return accepted;
  };
  const alternatives = (depth: number): boolean => {
    let accepted = conjunction(depth);
    while (tokens[index] === "OR") {
      index++;
      const next = conjunction(depth);
      accepted = accepted || next;
    }
    return accepted;
  };
  const accepted = alternatives(0);
  if (index !== tokens.length) throw new Error("SPDX expression contains trailing terms");
  return accepted;
}
