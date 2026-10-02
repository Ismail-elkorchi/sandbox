import { spawn } from "node:child_process";

/** Trusted build metadata, not a guest command executor. One bounded capture
 * completes only after stdio has closed, independently of process exit. */
export function captureCommand(command: string, arguments_: readonly string[],
  maximumBytes = 16 * 1024 ** 2, timeoutMs = 120_000): Promise<string> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 16 * 1024 ** 2
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new TypeError("invalid build capture envelope");
  }
  return new Promise((resolveCapture, rejectCapture) => {
    const output: Buffer[] = [];
    let count = 0;
    let diagnostic = Buffer.alloc(0);
    let failure: Error | undefined;
    const child = spawn(command, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    const fail = (error: Error): void => { failure ??= error; child.kill("SIGKILL"); };
    const timer = setTimeout(() => fail(new Error(`${command} exceeded its build capture deadline`)), timeoutMs);
    child.stdout.on("data", (bytes: Buffer) => {
      if (failure !== undefined) return;
      if (count + bytes.byteLength > maximumBytes) {
        fail(new Error(`${command} exceeded its build capture byte bound`)); return;
      }
      count += bytes.byteLength; output.push(bytes);
    });
    child.stderr.on("data", (bytes: Buffer) => {
      // Retain only a bounded diagnostic tail; never accumulate compiler logs.
      diagnostic = Buffer.concat([diagnostic, bytes.subarray(-4096)]).subarray(-4096);
    });
    child.stdout.once("error", fail);
    child.stderr.once("error", fail);
    child.once("error", fail);
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (failure !== undefined) { rejectCapture(failure); return; }
      if (code !== 0 || signal !== null) {
        rejectCapture(new Error(`${command} failed (${code ?? signal ?? "unknown"}): ${diagnostic.toString("utf8")}`)); return;
      }
      try { resolveCapture(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(output, count))); }
      catch { rejectCapture(new Error(`${command} returned invalid UTF-8 build metadata`)); }
    });
  });
}
