import { SandsurfHostError } from "./native-host.js";
import { sandsurfDigest } from "./sandsurf-protocol.js";
import { randomUUID } from "node:crypto";

export const transport = Symbol("host transport");

export const subscribe = Symbol("event subscription");

export const authorize = Symbol("host approval");

export const dispatchGuest = Symbol("guest command");

export const queryGuest = Symbol("guest query");

export const observed = Symbol("cached observation");

export const observe = Symbol("observe host response");

export const executionFence = Symbol("execution generation fence");

export function identity(prefix: string): string { return `${prefix}-${randomUUID()}`; }

export function childIdentity(operationId: string, part: string): string { return `op-${sandsurfDigest("operation", ["sandsurf-child-operation-v1", validateIdentity(operationId), part]).slice(0, 48)}`; }

export function validateIdentity(value: string): string { if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw new TypeError("Sandsurf identity is malformed"); return value; }

export function digest(value: string): string { if (!/^[a-f0-9]{64}$/u.test(value)) throw new TypeError("Sandsurf digest is malformed"); return value; }

export function protocol(subject: string): SandsurfHostError { return new SandsurfHostError("protocol", `native host returned an invalid ${subject}`); }
