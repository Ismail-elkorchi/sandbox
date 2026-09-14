# Detached execution repository

The repository binds each caller-owned executionId to one exact request. A closed client does not terminate a process. Execution outcome, control connectivity, and original-output availability are independent facts. Sandbox never replays an execution to resolve uncertainty.

This detached interface is a breaking replacement. Use a new private repository directory: incompatible records are rejected intact, without migration or recovery guesses. A former expired record cannot establish the lost outcome. Ordinary process/session APIs and platform eligibility requirements are unchanged.

## Prepare, authorize, observe, release

```ts
const repository = await openSandboxExecutionRepository({
  directory,
  maxRetainedExecutions: 128,
  maxRetainedIdentities: 16_384,
  maxTotalOutputBytes: 1024 * 1024 * 1024,
  maxTotalMetadataBytes: 1024 * 1024 * 1024,
});
const request = {
  executionId: "job-42",
  run: {
    isolation: { kind: "process" },
    policy,
    requirements: {},
    resources: {
      output: { enforcement: "hard", scope: "process", value: 8 * 1024 * 1024 },
    },
    process: {
      executable: { space: "isolated", path: "/tools/program" },
      cwd: { space: "isolated", path: "/workspace" },
      stdout: "pipe",
    },
  },
};
const prepared = await repository.prepare(request);
if (prepared.kind === "prepared") {
  await authorize(prepared); // Exact summary, enforcement and digests.
  await repository.activate(request.executionId, prepared);
}
const observation = await repository.inspect(request.executionId, { waitMs: 5_000 });

if (observation.kind === "settled" || observation.kind === "rejected") {
  let cursor = await loadDurableDeliveredCursor(request.executionId);
  while (cursor < observation.receipt.finalCursor) {
    const page = await repository.inspect(request.executionId, {
      afterCursor: cursor,
      maxBytes: 64 * 1024,
    });
    if (page.output.kind !== "available") throw new Error("Required output is unavailable");
    await durablyCaptureOriginalChunks(page.output.chunks);
    cursor = page.output.cursorEnd;
    await saveDurableDeliveredCursor(request.executionId, cursor);
  }
  await durablyConsumeReceipt(observation);
  await repository.forget(request.executionId, {
    receiptDigest: observation.receipt.digest,
  });
}
await repository.close();
```

An observation may still be preparing, prepared, running, or unknown; callers continue observation as appropriate. Passing the same retained identity to prepare never starts another effect. A different request using that identity is rejected. Activation requires exact prepared policy and execution digests. An unactivated preparation deadline still prevents starting the effect.

Settled observations contain the result, including cleanup and enforcement facts. Rejected observations contain the error and confirm no target execution. Both contain an immutable receipt binding the original identity, request, preparation evidence when available, outcome, final output cursor, stream byte counts, omissions, and final hash. Captured stdout/stderr are retrieved through output chunks and are not duplicated inside the result.

Receipts and output have no automatic retention deadline. Release requires the exact receipt digest and means the caller has durably consumed the evidence or explicitly accepts its loss. Repeating release with the same digest is safe, including after client death. A conflicting digest, live record, or uncertain effect is refused. Retirement leaves a compact identity tombstone, so release cannot authorize replay.

Retirement commits before deleting output. Until deletion finishes, a retired observation reports cleanupPending and its storage reservation remains charged. Repeating forget completes an interrupted release; inspection reports the exact pending operation without inventing an outcome.

acknowledgeUnknown separately accepts an unknown effect. It requires readable, unchanged retained authority and refuses a potentially live worker or admitting client. Corrupt records remain intact for diagnosis. Closing a client affects neither retention nor process lifetime.

## Output queries

inspect defaults to maxBytes: 0 and returns output.kind = "not-requested", without opening the log. Request up to 1 MiB per page and up to 30 seconds of observation wait. Output is discriminated independently:

- available: returned bytes and stream identities were verified; cursorEnd advances only across bytes delivered in this response.
- unavailable: requested original output is missing, corrupt, explicitly released, or could not be read.
- not-requested: no output access was performed.

A valid terminal receipt remains terminal when output is unavailable. Corrupt terminal evidence fails independently. availableCursorEnd is the verified available boundary for this observation; a smaller cursorEnd does not claim remaining bytes were delivered. Empty final pages retain the requested cursor. Invalid cursors are rejected. Receipt stream counts describe retained bytes; omittedStdoutBytes and omittedStderrBytes describe runtime-reported bytes not captured, including requested discard and output-limit omissions.

The reader range-reads JSONL byte records and their hash chain. A cold reader performs one integrity scan to construct sparse in-memory checkpoints. Subsequent polls scan newly appended records and verify requested ranges through a trusted checkpoint or final boundary. Checkpoints never become another output authority and are not persisted. Restart or cache eviction may require another cold scan; at most eight logs are cached per client. Detected replacement, truncation, or modification invalidates the cache, and every returned range is reverified. A partial trailing live record cannot advance either output cursor; any partial terminal record fails final-boundary verification.

Capture incrementally while running, then drain to the immutable final cursor before release. Preserve buffers and stream labels; independently decoding split UTF-8 chunks can change the rendering.

## Admission and inventory bounds

Capacity commits transactionally before starting a worker. Reopening requires the same storage limits; startupTimeoutMs is a per-client observation setting.

| Bound | Default |
| --- | --- |
| Retained executions, including unresolved effects and pending deletion | 128 |
| All identities, including retired tombstones | 16,384 |
| Original output bytes per execution | 16 MiB |
| Aggregate reserved original output bytes | 1 GiB |
| Aggregate reserved authority/receipt metadata | 1 GiB |

Each admission reserves its full requested hard output limit. Metadata reserves 8 MiB for bounded preparation/result records plus twice the requested artifact/change-set byte limits for stored hex content. These are logical reservations: JSONL/base64 framing, SQLite pages, and temporary transaction journals add disk overhead. Log records contain at most 16 KiB of original bytes; framing has a conservative physical bound of 512 times the original byte limit. Metadata and entry limits bound retained storage but do not guarantee underlying filesystem free space. Filesystem failures remain explicit.

Quota exhaustion rejects new work and never evicts accepted evidence. Completed deletion releases output and metadata reservations and the retained-execution slot. Compact retired identities continue to consume the identity budget. Manage repository generations and fresh logical identities deliberately when that budget is exhausted.

reconcile({ afterCursor, limit }) returns discriminated observations and an optional nextCursor. The default page limit is 50 and maximum is 100. Inventory cursors are insertion sequence numbers, unrelated to output cursors. Iterate until nextCursor is absent; concurrent insertions may appear in later pages. Single-identity inspection uses the catalog's unique identity index and never scans all executions.

## Control, publication, and durability

Transport diagnostics distinguish unreachable endpoint, timeout, authentication rejection, malformed or unauthenticated response, and rejected operation. Tokens and raw peer messages are excluded. A failed ping triggers bounded rereads of current committed state. It cannot replace a concurrently published terminal result with an older output snapshot.

Mutating control errors expose SandboxExecutionControlError.failure, delivery ("not-applied" or "unknown"), and the rechecked observation when available. Authentication and explicit rejection remain visible. Every command has an identity and digest; the worker records acceptance before mutation and application after completion. A lost response can be resolved when the matching applied record or exact activation/terminal state proves completion. Input is never resent automatically. The worker retains one latest delivery record, keeping metadata bounded; superseded or partially applied input remains uncertain. Observation retries are safe. Retrying caller input after ambiguous delivery is a new potentially duplicating action.

The private catalog uses Node's built-in node:sqlite API, immediate transactions, full synchronization, and bounded lock waits. The API is experimental in Node 24; no additional package or service is installed. See the [Node 24 SQLite documentation](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html).

The worker drains both streams and synchronizes retained output before atomically committing the complete terminal receipt. Result and terminal state have one publication authority, with no separate receipt/state recovery write. A stale publication cannot overwrite terminal truth. Application-process termination is the declared durability level. Worker loss before terminal commit can remain unknown; operating-system restart and power loss are not promised durability guarantees.

Repository-owned consumers and declarations use this contract. External consumers must update their Sandbox pin to the actual reviewed commit when available, adopting explicit receipt consumption and release together. There are no compatibility adapters or guessed future revisions.
