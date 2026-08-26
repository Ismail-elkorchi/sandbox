import type { Readable, Writable } from "node:stream";
import type { SandboxEvent, SandboxRunResult } from "./result.js";

export type SandboxProcessIdentity =
  | { kind: "host-process"; pid: number }
  | { kind: "guest-process"; pid: number }
  | { kind: "opaque" };

export interface SandboxProcess {
  readonly id: string;
  readonly identity: SandboxProcessIdentity;
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
  events(): AsyncIterable<SandboxEvent>;
  wait(): Promise<SandboxRunResult>;
  terminate(reason?: "cancelled" | "timeout" | "caller-request"): Promise<void>;
}
