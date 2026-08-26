import { Buffer } from "node:buffer";

export const PROTOCOL_MAJOR = 1;
export const PROTOCOL_MINOR = 0;
export const MAX_CONTROL_PAYLOAD = 1024 * 1024;
export const MAX_STREAM_PAYLOAD = 64 * 1024;
const HEADER_LENGTH = 12;
const MAGIC = Buffer.from("SBX1", "ascii");

export enum MessageType {
  Hello = 1,
  Probe = 2,
  PrepareRun = 3,
  StartPreparedRun = 4,
  CancelPreparedRun = 5,
  PrepareSession = 6,
  ActivateSession = 7,
  CancelPreparedSession = 8,
  PrepareProcess = 9,
  StartPreparedProcess = 10,
  CancelPreparedProcess = 11,
  Stdin = 12,
  CloseStdin = 13,
  StreamCredit = 14,
  Terminate = 15,
  CloseSession = 16,
  Shutdown = 17,
  HelloAck = 101,
  ProbeResult = 102,
  RunPrepared = 103,
  SessionPrepared = 104,
  SessionActive = 105,
  ProcessPrepared = 106,
  ProcessStarted = 107,
  Stdout = 108,
  Stderr = 109,
  Event = 110,
  ProcessExit = 111,
  SessionClosed = 112,
  Error = 113,
  RuntimeMetrics = 114,
  Artifact = 115,
}

export interface ProtocolFrame {
  messageType: MessageType;
  flags: number;
  payload: Buffer;
}

export class FrameDecodeError extends Error {}

export function encodeControlFrame(messageType: MessageType, value: unknown): Buffer {
  if (isBinaryMessage(messageType)) {
    throw new FrameDecodeError("binary message cannot carry control JSON");
  }
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  return encodeFrame(messageType, payload, MAX_CONTROL_PAYLOAD);
}

export function encodeBinaryFrame(messageType: MessageType, payload: Buffer): Buffer {
  if (!isBinaryMessage(messageType)) {
    throw new FrameDecodeError("control message cannot carry binary data");
  }
  return encodeFrame(messageType, payload, MAX_STREAM_PAYLOAD);
}

function encodeFrame(messageType: MessageType, payload: Buffer, maximum: number): Buffer {
  if (payload.byteLength > maximum) {
    throw new FrameDecodeError(`protocol payload exceeds ${maximum} bytes`);
  }
  const header = Buffer.alloc(HEADER_LENGTH);
  MAGIC.copy(header, 0);
  header[4] = messageType;
  header.writeUInt32BE(payload.byteLength, 8);
  return Buffer.concat([header, payload]);
}

export class FrameDecoder {
  #buffer: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): ProtocolFrame[] {
    if (chunk.byteLength !== 0) {
      this.#buffer = this.#buffer.byteLength === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);
    }
    const frames: ProtocolFrame[] = [];
    while (this.#buffer.byteLength >= HEADER_LENGTH) {
      if (!this.#buffer.subarray(0, 4).equals(MAGIC)) {
        throw new FrameDecodeError("invalid protocol magic");
      }
      const typeByte = this.#buffer[4];
      if (typeByte === undefined || !isMessageType(typeByte)) {
        throw new FrameDecodeError("unknown protocol message type");
      }
      if (this.#buffer[5] !== 0 || this.#buffer[6] !== 0 || this.#buffer[7] !== 0) {
        throw new FrameDecodeError("reserved protocol header bits are non-zero");
      }
      const length = this.#buffer.readUInt32BE(8);
      const maximum = isBinaryMessage(typeByte) ? MAX_STREAM_PAYLOAD : MAX_CONTROL_PAYLOAD;
      if (length > maximum) {
        throw new FrameDecodeError(`declared protocol payload exceeds ${maximum} bytes`);
      }
      if (this.#buffer.byteLength < HEADER_LENGTH + length) {
        break;
      }
      const payload = Buffer.from(this.#buffer.subarray(HEADER_LENGTH, HEADER_LENGTH + length));
      frames.push({ messageType: typeByte, flags: this.#buffer[5] ?? 0, payload });
      this.#buffer = this.#buffer.subarray(HEADER_LENGTH + length);
    }
    return frames;
  }

  finish(): void {
    if (this.#buffer.byteLength !== 0) {
      throw new FrameDecodeError("runtime protocol ended with a truncated frame");
    }
  }
}

export function decodeControl(frame: ProtocolFrame): unknown {
  if (isBinaryMessage(frame.messageType)) {
    throw new FrameDecodeError("binary protocol frame is not control JSON");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(frame.payload);
  return JSON.parse(text);
}

export function isBinaryMessage(messageType: MessageType): boolean {
  return (
    messageType === MessageType.Stdin ||
    messageType === MessageType.Stdout ||
    messageType === MessageType.Stderr
    || messageType === MessageType.Artifact
  );
}

function isMessageType(value: number): value is MessageType {
  return (
    (value >= MessageType.Hello && value <= MessageType.Shutdown) ||
    (value >= MessageType.HelloAck && value <= MessageType.Artifact)
  );
}
