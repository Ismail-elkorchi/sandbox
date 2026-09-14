import { Buffer } from "node:buffer";
import { createHmac, timingSafeEqual } from "node:crypto";
import net from "node:net";
import type { SandboxExecutionControlFailure, SandboxExecutionObservation } from "./execution.js";

const MESSAGES: Record<SandboxExecutionControlFailure, string> = {
  unreachable: "Execution control endpoint is unreachable.",
  timeout: "Execution control request timed out.",
  "authentication-rejected": "Execution control authentication was rejected.",
  "malformed-response": "Execution control response is malformed or unauthenticated.",
  "operation-rejected": "Execution control operation was rejected.",
};
export class SandboxExecutionControlError extends Error {
  override readonly name = "SandboxExecutionControlError";
  observation?: SandboxExecutionObservation;
  constructor(readonly failure: SandboxExecutionControlFailure, readonly delivery: "not-applied" | "unknown") {
    super(failure === "operation-rejected" && delivery === "unknown" ? "Execution control failed after acceptance; delivery outcome is unknown." : MESSAGES[failure]);
  }
}
export interface ControlCommand {
  id: string;
  kind: "ping" | "activate" | "write" | "close-input" | "terminate";
  policyDigest?: string; executionDigest?: string; dataBase64?: string;
}

export function controlResponse(token: string, id: string, failure?: "authentication-rejected" | "operation-rejected", delivery: "not-applied" | "unknown" = "not-applied"): string {
  const response = { id, accepted: failure === undefined, ...(failure === undefined ? {} : { failure, delivery }) };
  return JSON.stringify({ ...response, mac: mac(token, response) }) + "\n";
}

export async function sendControl(endpoint: number, token: string, command: ControlCommand): Promise<void> {
  if (!Number.isSafeInteger(endpoint) || endpoint < 1 || endpoint > 65_535) throw new SandboxExecutionControlError("unreachable", "not-applied");
  const payload = JSON.stringify({ token, ...command }) + "\n";
  if (Buffer.byteLength(payload) > 128 * 1024) throw new RangeError("Execution control request is too large.");
  await new Promise<void>((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port: endpoint });
    let sent = false; let completed = false; let response = Buffer.alloc(0);
    const fail = (failure: SandboxExecutionControlFailure, delivery: "not-applied" | "unknown" = sent ? "unknown" : "not-applied") => {
      if (completed) return;
      completed = true; socket.destroy(); reject(new SandboxExecutionControlError(failure, delivery));
    };
    socket.setTimeout(2_000, () => fail("timeout"));
    socket.once("connect", () => { sent = true; socket.write(payload); });
    socket.on("data", (chunk: Buffer) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > 4096) return fail("malformed-response");
      if (!response.includes(10)) return;
      try {
        const parsed: unknown = JSON.parse(response.toString("utf8"));
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return fail("malformed-response");
        const value = parsed as Record<string, unknown>;
        if (Object.keys(value).some((key) => !["id", "accepted", "failure", "delivery", "mac"].includes(key))) return fail("malformed-response");
        if (value.id !== command.id || typeof value.accepted !== "boolean" || typeof value.mac !== "string") return fail("malformed-response");
        if (value.failure !== undefined && value.failure !== "authentication-rejected" && value.failure !== "operation-rejected") return fail("malformed-response");
        if ((value.accepted && value.failure !== undefined) || (!value.accepted && value.failure === undefined)) return fail("malformed-response");
        const { mac: received, ...unsigned } = value;
        const expected = mac(token, unsigned);
        if (!/^[a-f0-9]{64}$/u.test(received) || !timingSafeEqual(Buffer.from(received, "hex"), Buffer.from(expected, "hex"))) return fail("malformed-response");
        if (!value.accepted) {
          if (value.delivery !== "not-applied" && value.delivery !== "unknown") return fail("malformed-response");
          return fail(value.failure as "authentication-rejected" | "operation-rejected", value.delivery);
        }
        completed = true; socket.destroy(); resolve();
      } catch { fail("malformed-response"); }
    });
    socket.once("error", () => fail("unreachable"));
    socket.once("end", () => fail("malformed-response"));
    socket.once("close", () => { if (!completed) fail("unreachable"); });
  });
}
function mac(token: string, value: unknown): string { return createHmac("sha256", token).update(JSON.stringify(value)).digest("hex"); }
