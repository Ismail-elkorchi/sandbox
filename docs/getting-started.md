# Getting started

Install Node.js 24 or newer and the package:

```sh
npm install @ismail-elkorchi/sandbox
```

Build a policy whose resources include every file tree the executable needs. Paths are tagged so host sources cannot be confused with target paths. See [the policy guide](policy.md) for a complete resource example.

Probe the exact request before offering execution:

```ts
const support = await sandbox.probe({
  isolation: options.isolation,
  policy: options.policy,
  requirements: options.requirements,
  resources: options.resources,
});

const eligible = support.implementations.find(
  (implementation) => implementation.eligibility.state === "eligible",
);
```

Availability describes mechanism support. Eligibility evaluates the supplied topology, policy, requirements, and limit scopes. Concrete path existence and identity are established during preparation.

For an approval flow, prepare first and authorize the returned values:

```ts
const prepared = await sandbox.prepareRun(options);
await authorize({
  summary: prepared.summary,
  enforcement: prepared.enforcement,
  policyDigest: prepared.policyDigest,
  executionDigest: prepared.executionDigest,
  expiresAtMs: prepared.expiresAtMs,
});

const process = await prepared.start({
  policyDigest: prepared.policyDigest,
  executionDigest: prepared.executionDigest,
});
const result = await process.wait();
```

`sandbox.run(options)` performs the same preparation and activation path when the caller is itself the authorization boundary.

A prepared session binds one immutable policy and selected implementation. Session processes use tagged executable and working-directory paths and run sequentially. Detached execution persists the same prepared identity; recovery never selects a different implementation.

Inspect structured termination, enforcement facts, usage, and cleanup independently. A normal process exit does not prove cleanup succeeded. Close sessions and call `sandbox.dispose()` in `finally` blocks.
