# Runtime protocol

The protocol connects the dependency-free TypeScript API to a package-owned Rust runtime over stdin and stdout. It is not a public network protocol, but it is treated as a hostile framing boundary because target behavior can influence streams, timing, artifacts, and lifecycle.

## Transport

Runtime stdin carries Node-to-Rust frames. Runtime stdout carries Rust-to-Node frames. Target stdout and stderr are always payloads inside valid protocol frames and are never copied directly to runtime stdout. Runtime stderr is reserved for bounded emergency diagnostics.

The runtime receives a minimal fixed environment and is executed from a verified package descriptor rather than through `PATH`.

## Frame format

Every frame has a 12-byte header followed by its declared payload:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `SBX1` |
| 4 | 1 | Message type |
| 5 | 3 | Reserved, all zero |
| 8 | 4 | Big-endian unsigned payload length |

Control payloads are fatal-UTF-8 JSON and are limited to 1 MiB. Binary stdin, stdout, stderr, artifact, and change-set chunks are limited to 64 KiB. A decoder rejects invalid magic, unknown message types, non-zero reserved bytes, invalid UTF-8/JSON, wrong payload classes, and declared lengths above the class limit before allocating the payload.

Decoders are incremental. Partial headers and payloads remain buffered until complete; end-of-stream with buffered bytes is a truncation error.

## Version negotiation

Protocol compatibility is negotiated by the initial `HELLO` / `HELLO_ACK` exchange. Major-version mismatch is fatal. Minor versions may add optional fields but cannot change existing field meaning. Unknown required fields or capabilities fail closed.

Header reserved bytes remain zero until a future protocol version explicitly defines them.

## Lifecycle

The main request families are:

- probe;
- prepare, start, and cancel one-shot runs;
- prepare, activate, and cancel sessions;
- prepare, start, and cancel session processes;
- stdin, stdin close, stream credit, termination, and output;
- events, artifacts, final process results, session close, and runtime shutdown.

Requests and prepared/runtime objects have identifiers. Duplicate response identifiers, impossible state transitions, output after final exit, exit before start, and shutdown with an unaccounted active process are protocol failures.

Prepared objects live only inside their owning runtime. They expire after their resolved TTL and are consumed by the first activation attempt. Start messages must carry the exact Rust-produced policy and execution digests.

## Stream flow control

Binary streams use explicit byte credits. A sender may not emit more bytes than currently granted, and credit arithmetic rejects overflow.

Credits are scoped to one process and reset when it completes. Output is counted against the hard aggregate output limit before protocol delivery, so a paused Node consumer cannot bypass the limit. Stdin credit is replenished only for bytes accepted by the target pipe, not merely buffered by an intermediate control socket.

Lifecycle and termination use independent control paths. A target that never reads stdin or a client that stops reading output cannot block the hard wall-time path.

## Errors and results

Runtime errors are structured and include a bounded code, lifecycle context, target-executed flag, and relevant backend/platform identity. They do not include environment values, unbounded target text, complete host paths unless explicitly safe, or raw backend diagnostics.

Final process messages contain structured termination, enforcement, resource use, violations, cleanup, and optional artifact/change-set metadata. Raw wait status is translated by the authoritative supervisor so signals and resource causes are not collapsed into ordinary numeric exits.

## Internal launcher and guest channels

The Linux supervisor-to-launcher channel uses a separate bounded incremental framing format plus descriptor passing. Its decoder preserves partial nonblocking frames.

The Firecracker host-to-guest channel runs over Virtio sockets and authenticates requests with a fresh per-VM nonce. Artifact and network subprotocols use bounded lengths, offsets, digests, and explicit completion. The target cannot access the guest control endpoint or nonce.

## Assurance

Protocol tests cover partial and truncated frames, reserved bits, length lies, duplicate identifiers, lifecycle ordering, credits, and active-process shutdown. The frame and control-message parsers also have libFuzzer targets. See [development.md](development.md).
