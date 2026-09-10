import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { constants, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import test from "node:test";
import { createSandbox } from "../dist/index.js";
import {
  baseOptions,
  isolatedPath,
  isolatedPolicy,
  isolatedResource,
  linuxImplementationEligible,
  readAccess,
  readWriteAccess,
  runtimeResources,
  shellProcess,
  withSandbox,
} from "./helpers.mjs";

const linux = await linuxImplementationEligible();

test("exact arguments are passed without an implicit shell", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: shellProcess(["-c", "printf '%s|%s' \"$1\" \"$2\"", "sandbox", "one two", "$(not-a-shell)"]),
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    assert.equal(result.stdout?.toString(), "one two|$(not-a-shell)");
  });
});

test("explicit resources, masks, and empty-by-default environment are enforced", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-resource-"));
  const outside = await mkdtemp(join(tmpdir(), "sandbox-outside-"));
  try {
    await writeFile(join(workspace, "input"), "hello");
    await writeFile(join(workspace, "secret"), "hidden");
    await writeFile(join(outside, "secret"), "host-secret");
    const resources = [
      ...runtimeResources(),
      isolatedResource("workspace", workspace, "/workspace", readWriteAccess(), ["data"]),
    ];
    await withSandbox(async (sandbox) => {
      const result = await sandbox.run({
        ...baseOptions({
          policy: isolatedPolicy(resources, {
            masks: [{ path: isolatedPath("/workspace/secret"), replacement: "inaccessible" }],
          }),
        }),
        process: shellProcess([
          "-c",
          "test \"$(cat input)\" = hello && ! cat secret >/dev/null 2>&1 && ! cat \"$OUTSIDE\" >/dev/null 2>&1 && printf '%s' \"$TOKEN\" > generated",
        ], {
          cwd: isolatedPath("/workspace"),
          environment: {
            set: {
              TOKEN: { value: "captured", sensitive: true },
              OUTSIDE: join(outside, "secret"),
            },
          },
        }),
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(await readFile(join(workspace, "generated"), "utf8"), "captured");
      assert.equal(JSON.stringify(result.enforcement).includes("captured"), false);
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("prepared executable bytes and identity survive source replacement", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-executable-"));
  try {
    const executable = join(workspace, "tool");
    await writeFile(executable, "#!/bin/sh\nprintf approved\n", { mode: 0o755 });
    const resources = [
      ...runtimeResources(),
      isolatedResource("tool", workspace, "/tool", readAccess("allow"), ["executable", "data"]),
    ];
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({ policy: isolatedPolicy(resources) }),
        process: {
          executable: isolatedPath("/tool/tool"),
          cwd: isolatedPath("/tool"),
        },
      });
      await rename(executable, join(workspace, "approved"));
      await writeFile(executable, "#!/bin/sh\nprintf replacement\n", { mode: 0o755 });
      const process_ = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process_.wait();
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.stdout?.toString(), "approved");
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("hard output and wall-time limits terminate the owned tree", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const output = await sandbox.run({
      ...baseOptions({
        resources: { output: { enforcement: "hard", scope: "process", value: 1_024 } },
      }),
      process: shellProcess(["-c", "while :; do printf 1234567890; done"]),
    });
    assert.deepEqual(output.termination, { reason: "output-limit" });
    assert.equal(output.stdout?.byteLength, 1_024);
    assert.equal(output.usage.stdoutBytes + output.usage.stderrBytes > 1_024, true);

    const timeout = await sandbox.run({
      ...baseOptions({
        resources: { wallTime: { enforcement: "hard", scope: "process", value: 100 } },
      }),
      process: shellProcess(["-c", "sleep 10"]),
    });
    assert.deepEqual(timeout.termination, { reason: "timeout" });
    assert.equal(timeout.cleanup.completed, true);
  });
});

test("prepared sessions use the same policy and execute sequential processes", { skip: !linux }, async () => {
  const sandbox = await createSandbox();
  try {
    const prepared = await sandbox.prepareSession(baseOptions());
    const session = await prepared.activate({ policyDigest: prepared.policyDigest });
    try {
      const first = await session.run(shellProcess(["-c", "printf one"]));
      const second = await session.run(shellProcess(["-c", "printf two"]));
      assert.equal(first.stdout?.toString(), "one");
      assert.equal(second.stdout?.toString(), "two");
    } finally {
      await session.close();
    }
  } finally {
    await sandbox.dispose();
  }
});

test("preparation cancellation executes no target", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-cancel-"));
  const sentinel = join(workspace, "sentinel");
  try {
    const resources = [
      ...runtimeResources(),
      isolatedResource("workspace", workspace, "/workspace", readWriteAccess(), ["data"]),
    ];
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({ policy: isolatedPolicy(resources) }),
        process: shellProcess(["-c", "printf ran > sentinel"], { cwd: isolatedPath("/workspace") }),
      });
      await prepared.cancel();
      await assert.rejects(access(sentinel, constants.F_OK));
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("prepared executable bytes survive in-place source mutation", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-executable-content-"));
  try {
    const executable = join(workspace, "tool");
    await writeFile(executable, "#!/bin/sh\nprintf approved\n", { mode: 0o755 });
    const resources = [
      ...runtimeResources(),
      isolatedResource("tool", workspace, "/tool", readAccess("allow"), ["executable", "data"]),
    ];
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({ policy: isolatedPolicy(resources) }),
        process: { executable: isolatedPath("/tool/tool"), cwd: isolatedPath("/tool") },
      });
      await writeFile(executable, "#!/bin/sh\nprintf mutated!\n", { mode: 0o755 });
      const process_ = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process_.wait();
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.stdout?.toString(), "approved");
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("prepared resource and working-directory identities survive path replacement", { skip: !linux }, async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-directory-race-"));
  const workspace = join(parent, "workspace");
  const approved = join(parent, "approved");
  try {
    await mkdir(workspace);
    await writeFile(join(workspace, "identity"), "approved");
    const resources = [
      ...runtimeResources(),
      isolatedResource("workspace", workspace, "/workspace", readWriteAccess(), ["data"]),
    ];
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({ policy: isolatedPolicy(resources) }),
        process: shellProcess(["-c", "cat identity; printf retained > result"], {
          cwd: isolatedPath("/workspace"),
        }),
      });
      await rename(workspace, approved);
      await mkdir(workspace);
      await writeFile(join(workspace, "identity"), "replacement");
      const process_ = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process_.wait();
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.stdout?.toString(), "approved");
      assert.equal(await readFile(join(approved, "result"), "utf8"), "retained");
      await assert.rejects(access(join(workspace, "result"), constants.F_OK));
    });
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("resource root links are resolved once or rejected according to policy", { skip: !linux }, async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-root-link-"));
  const original = join(parent, "original");
  const replacement = join(parent, "replacement");
  const link = join(parent, "link");
  try {
    await mkdir(original);
    await mkdir(replacement);
    await writeFile(join(original, "value"), "original");
    await writeFile(join(replacement, "value"), "replacement");
    await symlink(original, link);
    const request = (rootResolution) => ({
      ...baseOptions({
        policy: isolatedPolicy([
          ...runtimeResources(),
          {
            ...isolatedResource("workspace", link, "/workspace", readAccess(), ["data"]),
            rootResolution,
          },
        ]),
      }),
      process: {
        executable: isolatedPath("/bin/cat"),
        args: ["/workspace/value"],
        cwd: isolatedPath("/workspace"),
      },
    });
    await withSandbox(async (sandbox) => {
      await assert.rejects(() => sandbox.prepareRun(request("reject-if-link")));
      const prepared = await sandbox.prepareRun(request("resolve-once"));
      await rm(link);
      await symlink(replacement, link);
      const process_ = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process_.wait();
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.stdout?.toString(), "original");
    });
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("prepared shebang scripts execute the approved snapshot", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-script-"));
  try {
    const script = join(workspace, "approved-script");
    await writeFile(script, "#!/bin/sh\nprintf approved\n", { mode: 0o755 });
    const resources = [
      ...runtimeResources(),
      isolatedResource("script", workspace, "/workspace", readAccess("allow"), ["executable", "data"]),
    ];
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({ policy: isolatedPolicy(resources) }),
        process: { executable: isolatedPath("/workspace/approved-script"), cwd: isolatedPath("/workspace") },
      });
      await writeFile(script, "#!/bin/sh\nprintf replacement\n", { mode: 0o755 });
      const process_ = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process_.wait();
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.stdout?.toString(), "approved");
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("targets inherit no launcher setup descriptors", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: shellProcess([
        "-c",
        "for fd in 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do test ! -e /proc/self/fd/$fd || exit 87; done",
      ]),
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
  });
});

test("implementation-owned and overlapping resource targets fail before launch", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-reserved-target-"));
  try {
    await writeFile(join(workspace, "sentinel"), "preserved");
    await withSandbox(async (sandbox) => {
      for (const target of ["/", "/.sandbox-masks", "/etc", "/dev/null", "/proc/self"]) {
        const policy = isolatedPolicy([
          ...runtimeResources(),
          isolatedResource("invalid", workspace, target, readWriteAccess(), ["data"]),
        ]);
        await assert.rejects(() => sandbox.prepareRun({
          ...baseOptions({ policy }),
          process: shellProcess(),
        }));
      }
      const overlapping = isolatedPolicy([
        ...runtimeResources(),
        isolatedResource("workspace", workspace, "/workspace", readWriteAccess(), ["data"]),
        isolatedResource("nested", workspace, "/workspace/nested", readAccess(), ["data"]),
      ]);
      await assert.rejects(() => sandbox.prepareRun({
        ...baseOptions({ policy: overlapping }),
        process: shellProcess(),
      }));
    });
    assert.equal(await readFile(join(workspace, "sentinel"), "utf8"), "preserved");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("mask traversal through a resource symlink cannot reach host paths", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-mask-link-"));
  const outside = await mkdtemp(join(tmpdir(), "sandbox-mask-outside-"));
  try {
    await writeFile(join(outside, "secret"), "preserved");
    await symlink(outside, join(workspace, "link"));
    const resources = [
      ...runtimeResources(),
      isolatedResource("workspace", workspace, "/workspace", readWriteAccess(), ["data"]),
    ];
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({
          policy: isolatedPolicy(resources, {
            masks: [{ path: isolatedPath("/workspace/link/secret"), replacement: "inaccessible" }],
          }),
        }),
        process: shellProcess(["-c", "printf ran > /workspace/ran"], {
          cwd: isolatedPath("/workspace"),
        }),
      });
      await assert.rejects(() => prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      }));
    });
    assert.equal(await readFile(join(outside, "secret"), "utf8"), "preserved");
    await assert.rejects(access(join(workspace, "ran"), constants.F_OK));
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("read-only resources deny content, name, metadata, and link mutations", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-readonly-"));
  try {
    const file = join(workspace, "file");
    await writeFile(file, "preserved", { mode: 0o640 });
    const before = await stat(file);
    const resources = [
      ...runtimeResources(),
      isolatedResource("workspace", workspace, "/workspace", readAccess(), ["data"]),
    ];
    await withSandbox(async (sandbox) => {
      const result = await sandbox.run({
        ...baseOptions({
          policy: isolatedPolicy(resources, {
            temporary: { path: isolatedPath("/tmp"), sizeBytes: 1024 * 1024 },
          }),
        }),
        process: shellProcess([
          "-c",
          "test \"$(cat /workspace/file)\" = preserved && ! sh -c 'printf changed > /workspace/file' 2>/dev/null && ! touch /workspace/file 2>/dev/null && ! chmod 777 /workspace/file 2>/dev/null && ! mv /workspace/file /workspace/moved 2>/dev/null && ! ln /workspace/file /tmp/linked 2>/dev/null && ! mkdir /workspace/new 2>/dev/null",
        ]),
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    });
    const after = await stat(file);
    assert.equal(await readFile(file, "utf8"), "preserved");
    assert.equal(after.mode & 0o777, before.mode & 0o777);
    assert.equal(after.mtimeMs, before.mtimeMs);
    await assert.rejects(access(join(workspace, "moved"), constants.F_OK));
    await assert.rejects(access(join(workspace, "new"), constants.F_OK));
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("isolated names and explicitly synthetic directories hide host state", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions({
        policy: isolatedPolicy(runtimeResources(), {
          privateHome: { path: isolatedPath("/home/sandbox"), sizeBytes: 1024 * 1024 },
          temporary: { path: isolatedPath("/tmp"), sizeBytes: 1024 * 1024 },
        }),
      }),
      process: shellProcess([
        "-c",
        "test ! -e /root && test ! -e /opt && test ! -e /usr/local && test ! -e /dev/kvm && test ! -e /var/run/docker.sock && test -d /home/sandbox && test \"$(stat -c %a /tmp)\" = 1777",
      ]),
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
  });
});

test("binary stdin and capture remain byte-exact", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions(),
      process: shellProcess(["-c", "cat"], { stdin: "pipe" }),
    });
    const process_ = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
    const bytes = Buffer.from([0, 1, 2, 127, 128, 255]);
    process_.stdin?.end(bytes);
    const result = await process_.wait();
    assert.equal(result.stdout?.equals(bytes), true);
  });
});

test("network-none blocks direct external, loopback, and host IPC connections", { skip: !linux }, async (context) => {
  if (!existsSync("/usr/bin/python3")) {
    context.skip("python3 is not installed on this host");
    return;
  }
  const name = `\0sandbox-conformance-${process.pid}-${Date.now()}`;
  const server = createServer(() => {});
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(name, resolveListen);
  });
  try {
    await withSandbox(async (sandbox) => {
      const script = [
        "import socket,sys",
        "targets=[('1.1.1.1',80),('127.0.0.1',1),('::1',1)]",
        "for host,port in targets:",
        " s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)",
        " s.settimeout(.2)",
        " try: s.connect((host,port)); sys.exit(9)",
        " except OSError: pass",
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)",
        "s.settimeout(.2)",
        `name=${JSON.stringify(name)}`,
        "try: s.connect(name); sys.exit(10)",
        "except OSError: sys.exit(0)",
      ].join("\n");
      const result = await sandbox.run({
        ...baseOptions(),
        process: {
          executable: isolatedPath("/usr/bin/python3"),
          args: ["-c", script],
          cwd: isolatedPath("/"),
        },
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    });
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test("managed networking brokers allowed TCP and reports denied destinations", { skip: !linux }, async (context) => {
  if (!existsSync("/usr/bin/python3")) {
    context.skip("python3 is not installed on this host");
    return;
  }
  const server = createServer((socket) => {
    socket.once("data", () => {
      socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    assert.ok(address);
    const proxyScript = [
      "import os,socket,urllib.parse",
      "proxy=urllib.parse.urlsplit(os.environ['HTTP_PROXY'])",
      "s=socket.create_connection((proxy.hostname,proxy.port),2)",
      `s.sendall(b'CONNECT 127.0.0.1:${address.port} HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n\\r\\n')`,
      "head=s.recv(4096)",
      "assert b' 200 ' in head,head",
      "s.sendall(b'GET / HTTP/1.1\\r\\nHost: local\\r\\nConnection: close\\r\\n\\r\\n')",
      "data=b''",
      "while True:",
      " chunk=s.recv(4096)",
      " if not chunk: break",
      " data+=chunk",
      "assert data.endswith(b'ok'),data",
    ].join("\n");
    await withSandbox(async (sandbox) => {
      const network = {
        mode: "managed",
        allow: [{ transport: "tcp", destination: { kind: "ip", cidr: "127.0.0.1/32" }, ports: [address.port] }],
      };
      const allowed = await sandbox.run({
        ...baseOptions({ policy: isolatedPolicy(runtimeResources(), { network }) }),
        process: {
          executable: isolatedPath("/usr/bin/python3"),
          args: ["-c", proxyScript],
          cwd: isolatedPath("/"),
        },
      });
      assert.deepEqual(allowed.termination, { reason: "exit", code: 0 });
      assert.equal(allowed.usage.networkConnections, 1);

      const deniedScript = proxyScript.replace(
        "assert b' 200 ' in head,head",
        "assert b' 200 ' not in head,head; raise SystemExit(0)",
      );
      const denied = await sandbox.run({
        ...baseOptions({
          policy: isolatedPolicy(runtimeResources(), { network: { mode: "managed", allow: [] } }),
        }),
        process: {
          executable: isolatedPath("/usr/bin/python3"),
          args: ["-c", deniedScript],
          cwd: isolatedPath("/"),
        },
      });
      assert.deepEqual(denied.termination, { reason: "exit", code: 0 });
      assert.equal(denied.violations.some((violation) => violation.kind === "network-denied"), true);
    });
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test("nested namespaces remain unavailable to sandboxed processes", { skip: !linux }, async (context) => {
  if (!existsSync("/usr/bin/unshare")) {
    context.skip("unshare is not installed on this host");
    return;
  }
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: {
        executable: isolatedPath("/usr/bin/unshare"),
        args: ["--user", "--map-root-user", "/bin/true"],
        cwd: isolatedPath("/"),
      },
    });
    assert.equal(result.termination.reason, "exit");
    assert.notEqual(result.termination.code, 0);
  });
});

test("wall time continues under output and stdin backpressure", { skip: !linux }, async () => {
  const wallTime = { enforcement: "hard", scope: "process", value: 100 };
  await withSandbox(async (sandbox) => {
    const outputPrepared = await sandbox.prepareRun({
      ...baseOptions({ resources: { wallTime } }),
      process: shellProcess(["-c", "yes blocked"], { stdout: "pipe" }),
    });
    const outputProcess = await outputPrepared.start({
      policyDigest: outputPrepared.policyDigest,
      executionDigest: outputPrepared.executionDigest,
    });
    assert.deepEqual((await outputProcess.wait()).termination, { reason: "timeout" });

    const stdinPrepared = await sandbox.prepareRun({
      ...baseOptions({ resources: { wallTime } }),
      process: shellProcess(["-c", "sleep 10"], { stdin: "pipe" }),
    });
    const stdinProcess = await stdinPrepared.start({
      policyDigest: stdinPrepared.policyDigest,
      executionDigest: stdinPrepared.executionDigest,
    });
    stdinProcess.stdin?.write(Buffer.alloc(1024 * 1024));
    assert.deepEqual((await stdinProcess.wait()).termination, { reason: "timeout" });
  });
});

test("single-file, memory, and descendant process limits retain attribution", { skip: !linux }, async (context) => {
  await withSandbox(async (sandbox) => {
    const file = await sandbox.run({
      ...baseOptions({
        policy: isolatedPolicy(runtimeResources(), {
          temporary: { path: isolatedPath("/tmp"), sizeBytes: 8 * 1024 * 1024 },
        }),
        resources: { singleFileSize: { enforcement: "hard", scope: "process", value: 1024 } },
      }),
      process: {
        executable: isolatedPath("/bin/dd"),
        args: ["if=/dev/zero", "of=/tmp/large", "bs=4096", "count=1"],
        cwd: isolatedPath("/"),
      },
    });
    assert.deepEqual(file.termination, { reason: "single-file-size-limit" });

    const processRequest = {
      ...baseOptions({
        resources: { processCount: { enforcement: "hard", scope: "descendant-tree", value: 2 } },
      }),
      process: shellProcess(["-c", "for i in 1 2 3 4; do sleep 1 & done; wait"]),
    };
    await verifyAggregateLimit(sandbox, processRequest, "process-limit");

    if (!existsSync("/usr/bin/python3")) {
      context.diagnostic("python3 is absent; memory-limit subcase was not run");
      return;
    }
    const memoryRequest = {
      ...baseOptions({
        resources: {
          memory: { enforcement: "hard", scope: "descendant-tree", value: 32 * 1024 * 1024 },
          wallTime: { enforcement: "hard", scope: "process", value: 10_000 },
        },
      }),
      process: {
        executable: isolatedPath("/usr/bin/python3"),
        args: ["-c", "x=bytearray(256*1024*1024); x[::4096]=b'x'*(len(x)//4096); print(len(x))"],
        cwd: isolatedPath("/"),
      },
    };
    await verifyAggregateLimit(sandbox, memoryRequest, "memory-limit");
  });
});

async function verifyAggregateLimit(sandbox, request, reason) {
  const { process: target, ...policy } = request;
  const support = await sandbox.probe(policy);
  if (support.implementations.some((implementation) => implementation.eligibility.state === "eligible")) {
    const result = await sandbox.run({ ...policy, process: target });
    assert.deepEqual(result.termination, { reason });
  } else {
    await assert.rejects(() => sandbox.prepareRun(request), (error) =>
      error.data?.code === "unsupported.no_eligible_implementation" && error.data.targetExecuted === false);
  }
}

test("normal exit cannot leave daemonized descendants", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-tree-"));
  try {
    const resources = [
      ...runtimeResources(),
      isolatedResource("workspace", workspace, "/workspace", readWriteAccess(), ["data"]),
    ];
    await withSandbox(async (sandbox) => {
      const result = await sandbox.run({
        ...baseOptions({ policy: isolatedPolicy(resources) }),
        process: shellProcess(["-c", "(sleep .5; echo escaped > /workspace/escaped) & exit 0"], {
          cwd: isolatedPath("/workspace"),
        }),
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 700));
      await assert.rejects(access(join(workspace, "escaped"), constants.F_OK));
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("signals and ordinary stderr retain structured attribution", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const permissionText = await sandbox.run({
      ...baseOptions(),
      process: shellProcess(["-c", "echo permission denied >&2; exit 7"]),
    });
    assert.deepEqual(permissionText.termination, { reason: "exit", code: 7 });
    assert.equal(permissionText.stderr?.toString().trim(), "permission denied");
    assert.deepEqual(permissionText.violations, []);

    const signal = await sandbox.run({
      ...baseOptions(),
      process: shellProcess(["-c", "kill -TERM $$"]),
    });
    assert.deepEqual(signal.termination, { reason: "signal", signal: "SIGTERM" });
    assert.equal(signal.cleanup.completed, true);
  });
});

test("SIGKILL of the supervisor cannot orphan the launcher tree", { skip: !linux }, async () => {
  const before = new Set(await directChildren(process.pid));
  const sandbox = await createSandbox();
  try {
    const prepared = await sandbox.prepareRun({
      ...baseOptions({
        resources: { wallTime: { enforcement: "hard", scope: "process", value: 30_000 } },
      }),
      process: shellProcess(["-c", "sleep 30"]),
    });
    const target = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
    const runtimePid = (await directChildren(process.pid)).find((pid) => !before.has(pid));
    assert.ok(runtimePid, "runtime child PID must be discoverable for the crash test");
    const ownedTree = await descendants(runtimePid);
    assert.equal(ownedTree.length >= 2, true, "launcher and namespace target must exist");
    process.kill(runtimePid, "SIGKILL");
    await assert.rejects(target.wait());
    await waitUntil(async () => {
      const remaining = await Promise.all(ownedTree.map(async (pid) => processExists(pid)));
      return remaining.every((exists) => !exists);
    }, 5000);
  } finally {
    await sandbox.dispose();
  }
});

async function directChildren(pid) {
  try {
    const value = await readFile(`/proc/${pid}/task/${pid}/children`, "utf8");
    return value.trim() === "" ? [] : value.trim().split(/\s+/u).map(Number);
  } catch {
    return [];
  }
}

async function descendants(rootPid) {
  const values = [];
  const pending = [rootPid];
  while (pending.length > 0) {
    const parent = pending.shift();
    if (parent === undefined) break;
    const children = await directChildren(parent);
    values.push(...children);
    pending.push(...children);
  }
  return values;
}

function processExists(pid) {
  return access(`/proc/${pid}`, constants.F_OK).then(() => true, () => false);
}

async function waitUntil(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
  }
  assert.fail("condition did not become true before its deadline");
}

test("symbolic links resolve only through admitted, unmasked executable resources", { skip: !linux }, async () => {
  const root = await mkdtemp(join(tmpdir(), "sandbox-visible-links-"));
  try {
    const entry = join(root, "entry");
    const tools = join(root, "tools");
    await mkdir(entry);
    await mkdir(tools);
    await writeFile(join(tools, "tool"), "#!/bin/sh\nprintf approved", { mode: 0o755 });
    await symlink("/tools/tool", join(entry, "tool"));
    const resources = [
      ...runtimeResources(),
      isolatedResource("entry", entry, "/entry", readAccess("allow"), ["executable"]),
      isolatedResource("tools", tools, "/tools", readAccess("allow"), ["executable"]),
    ];
    await withSandbox(async (sandbox) => {
      const request = (admitted, masks = []) => ({
        ...baseOptions({ policy: isolatedPolicy(admitted, { masks }) }),
        process: { executable: isolatedPath("/entry/tool"), cwd: isolatedPath("/") },
      });
      const allowed = await sandbox.run(request(resources));
      assert.equal(allowed.stdout.toString(), "approved");
      await assert.rejects(() => sandbox.prepareRun(request(resources.slice(0, -1))));
      await assert.rejects(() => sandbox.prepareRun(request(resources, [
        { path: isolatedPath("/tools/tool"), replacement: "inaccessible" },
      ])));
      await assert.rejects(() => sandbox.prepareRun(request([
        ...resources.slice(0, -1), { ...resources.at(-1), access: readAccess("deny") },
      ])));
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("targets cannot inspect the isolated supervisor's retained authority", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: shellProcess(["-c", "! readlink /proc/1/fd/0 >/dev/null 2>&1 && ! cat /proc/1/mem >/dev/null 2>&1"]),
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
  });
});

test("normal exit preserves output beyond the credit window for a delayed consumer", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions(),
      process: {
        executable: isolatedPath("/bin/dd"),
        args: ["if=/dev/zero", "bs=65536", "count=17", "status=none"],
        cwd: isolatedPath("/"),
        stdout: "pipe",
      },
    });
    const target = await prepared.start({ policyDigest: prepared.policyDigest, executionDigest: prepared.executionDigest });
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
    const chunks = [];
    for await (const chunk of target.stdout) chunks.push(chunk);
    assert.deepEqual((await target.wait()).termination, { reason: "exit", code: 0 });
    assert.deepEqual(Buffer.concat(chunks), Buffer.alloc(17 * 65536));
  });
});

test("a session can consume completed output while another process runs", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareSession(baseOptions());
    const session = await prepared.activate({ policyDigest: prepared.policyDigest });
    try {
      const firstPlan = await session.prepare({
        executable: isolatedPath("/bin/dd"),
        args: ["if=/dev/zero", "bs=65536", "count=8", "status=none"],
        cwd: isolatedPath("/"), stdout: "pipe",
      });
      const first = await firstPlan.start({ policyDigest: firstPlan.policyDigest, executionDigest: firstPlan.executionDigest });
      await first.wait();
      const second = session.run(shellProcess(["-c", "sleep .1; printf second"]));
      let bytes = 0;
      for await (const chunk of first.stdout) bytes += chunk.length;
      assert.equal(bytes, 8 * 65536);
      assert.equal((await second).stdout.toString(), "second");
    } finally {
      await session.close();
    }
  });
});

test("killing the namespace launcher reaps its tree while the session supervisor survives", { skip: !linux }, async () => {
  const before = new Set(await directChildren(process.pid));
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareSession(baseOptions());
    const session = await prepared.activate({ policyDigest: prepared.policyDigest });
    try {
      const plan = await session.prepare(shellProcess(["-c", "sleep 30"]));
      const target = await plan.start({ policyDigest: plan.policyDigest, executionDigest: plan.executionDigest });
      const supervisor = (await directChildren(process.pid)).find((pid) => !before.has(pid));
      assert.ok(supervisor);
      const [launcher] = await directChildren(supervisor);
      assert.ok(launcher);
      const tree = await descendants(supervisor);
      process.kill(launcher, "SIGKILL");
      await waitUntil(async () => (await Promise.all(tree.map(processExists))).every((exists) => !exists), 5000);
      assert.equal(await processExists(supervisor), true);
      const result = await target.wait();
      assert.notEqual(result.termination.reason, "exit");
    } finally {
      await session.close();
    }
  });
});
