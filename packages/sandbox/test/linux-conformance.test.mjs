import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import test from "node:test";
import { createSandbox } from "../dist/index.js";
import { baseOptions, withSandbox } from "./helpers.mjs";

const linux = process.platform === "linux" && await (async () => {
  const sandbox = await createSandbox();
  try {
    const support = await sandbox.probe();
    return support.backends.some((backend) => backend.id === "linux-namespace-v1" && backend.available);
  } catch {
    return false;
  } finally {
    await sandbox.dispose();
  }
})();

test("exact arguments are binary-safe and no shell is implicit", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: {
        executable: "/bin/printf",
        args: ["%s|%s", "one two", "$(not-a-shell)"],
        cwd: "/",
      },
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    assert.equal(result.stdout?.toString(), "one two|$(not-a-shell)");
  });
});

test("prepared summaries redact values while execution receives the captured environment", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions(),
      process: {
        executable: "/bin/sh",
        args: ["-c", "printf %s \"$TOKEN\""],
        cwd: "/",
        environment: {
          base: "empty",
          set: { TOKEN: { value: "not-for-summary", sensitive: true } },
        },
      },
    });
    assert.deepEqual(prepared.summary.execution.environmentNames, ["TOKEN"]);
    assert.deepEqual(prepared.summary.execution.sensitiveEnvironmentNames, ["TOKEN"]);
    assert.equal(JSON.stringify(prepared.summary).includes("not-for-summary"), false);
    assert.equal(JSON.stringify(prepared.enforcement).includes("not-for-summary"), false);
    const process = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
    const result = await process.wait();
    assert.equal(result.stdout?.toString(), "not-for-summary");
  });
});

test("explicit grants, masks, private paths, and synthetic identity files are enforced", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-grant-"));
  try {
    await writeFile(join(workspace, "input"), "hello");
    await writeFile(join(workspace, "secret"), "hidden");
    await withSandbox(async (sandbox) => {
      const options = baseOptions({
        policy: {
          filesystem: {
            runtime: { kind: "system" },
            grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read-write" }],
            masks: [{ targetPath: "/workspace/secret" }],
          },
          network: { mode: "none" },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
      });
      const result = await sandbox.run({
        ...options,
        process: {
          executable: "/bin/sh",
          args: [
            "-c",
            "test \"$(pwd)\" = /workspace && test \"$(cat input)\" = hello && ! cat secret >/dev/null 2>&1 && ! test -e /root && grep -q '^sandbox:' /etc/passwd && printf world > generated",
          ],
          cwd: "/workspace",
        },
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(await readFile(join(workspace, "generated"), "utf8"), "world");
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("prepared executable identity survives replacement", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-executable-race-"));
  try {
    const executable = join(workspace, "tool.sh");
    await writeFile(executable, "#!/bin/sh\nprintf approved\n", { mode: 0o755 });
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read", execution: "allow" }],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: { executable: "/workspace/tool.sh", cwd: "/workspace" },
      });
      await rename(executable, join(workspace, "approved.sh"));
      await writeFile(executable, "#!/bin/sh\nprintf replacement\n", { mode: 0o755 });
      const process = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process.wait();
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.stdout?.toString(), "approved");
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("prepared executable bytes survive in-place source mutation", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-executable-content-"));
  try {
    const executable = join(workspace, "tool.sh");
    await writeFile(executable, "#!/bin/sh\nprintf approved\n", { mode: 0o755 });
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read", execution: "allow" }],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: { executable: "/workspace/tool.sh", cwd: "/workspace" },
      });
      await writeFile(executable, "#!/bin/sh\nprintf mutated!\n", { mode: 0o755 });
      const process = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process.wait();
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.stdout?.toString(), "approved");
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("prepared grant and working-directory descriptors survive path replacement", { skip: !linux }, async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-directory-race-"));
  const workspace = join(parent, "workspace");
  const approved = join(parent, "approved");
  try {
    await mkdir(workspace);
    await writeFile(join(workspace, "identity"), "approved");
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read-write" }],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: {
          executable: "/bin/sh",
          args: ["-c", "cat identity; printf retained > result"],
          cwd: "/workspace",
        },
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

test("grant root symlinks are resolved once or rejected according to policy", { skip: !linux }, async () => {
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
    await withSandbox(async (sandbox) => {
      const request = (rootResolution) => ({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [{ hostPath: link, targetPath: "/workspace", access: "read", rootResolution }],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: { executable: "/bin/cat", args: ["/workspace/value"], cwd: "/workspace" },
      });
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
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun(baseOptions({
        policy: {
          filesystem: {
            runtime: { kind: "system" },
            grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read", execution: "allow" }],
          },
          network: { mode: "none" },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
        process: { executable: "/workspace/approved-script", cwd: "/workspace" },
      }));
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
      process: {
        executable: "/bin/sh",
        args: ["-c", "for fd in 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do test ! -e /proc/self/fd/$fd || exit 87; done"],
        cwd: "/",
      },
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
  });
});

test("runtime-owned targets and overlapping grants fail before launch", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-reserved-target-"));
  try {
    await writeFile(join(workspace, "sentinel"), "preserved");
    await withSandbox(async (sandbox) => {
      for (const targetPath of ["/", "/.sandbox-masks", "/tmp/work", "/home", "/etc", "/dev/null", "/proc/self"]) {
        await assert.rejects(() => sandbox.prepareRun({
          ...baseOptions({
            policy: {
              filesystem: {
                runtime: { kind: "system" },
                grants: [{ hostPath: workspace, targetPath, access: "read-write" }],
              },
              network: { mode: "none" },
              process: { hostProcesses: "deny", hostIpc: "deny" },
            },
          }),
          process: { executable: "/bin/true", cwd: "/" },
        }));
      }
      await assert.rejects(() => sandbox.prepareRun({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [
                { hostPath: workspace, targetPath: "/workspace", access: "read-write" },
                { hostPath: workspace, targetPath: "/workspace/nested", access: "read" },
              ],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: { executable: "/bin/true", cwd: "/" },
      }));
    });
    assert.equal(await readFile(join(workspace, "sentinel"), "utf8"), "preserved");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("mask traversal through a grant symlink cannot reach host paths", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-mask-link-"));
  const outside = await mkdtemp(join(tmpdir(), "sandbox-mask-outside-"));
  try {
    await writeFile(join(outside, "secret"), "preserved");
    await symlink(outside, join(workspace, "link"));
    await withSandbox(async (sandbox) => {
      const prepared = await sandbox.prepareRun({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read-write" }],
              masks: [{ targetPath: "/workspace/link/secret" }],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: {
          executable: "/bin/sh",
          args: ["-c", "printf ran > /workspace/ran"],
          cwd: "/workspace",
        },
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

test("read-only grants deny content, namespace, metadata, and cross-boundary link mutations", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-readonly-"));
  try {
    const file = join(workspace, "file");
    await writeFile(file, "preserved", { mode: 0o640 });
    const before = await stat(file);
    await withSandbox(async (sandbox) => {
      const result = await sandbox.run({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read" }],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: {
          executable: "/bin/sh",
          args: [
            "-c",
            "test \"$(cat /workspace/file)\" = preserved && ! sh -c 'printf changed > /workspace/file' 2>/dev/null && ! touch /workspace/file 2>/dev/null && ! chmod 777 /workspace/file 2>/dev/null && ! mv /workspace/file /workspace/moved 2>/dev/null && ! ln /workspace/file /tmp/linked 2>/dev/null && ! mkdir /workspace/new 2>/dev/null",
          ],
          cwd: "/",
        },
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

test("synthetic runtime hides host data, runtime sockets, devices, and user toolchains", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: {
        executable: "/bin/sh",
        args: [
          "-c",
          "test ! -e /root && test ! -e /run && test ! -e /opt && test ! -e /usr/local && test ! -e /dev/kvm && test ! -e /var/run/docker.sock && test \"$(stat -c %a /tmp)\" = 1777",
        ],
        cwd: "/",
      },
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
  });
});

test("binary stdin and capture remain byte-exact", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions(),
      process: { executable: "/bin/sh", args: ["-c", "cat"], cwd: "/", stdin: "pipe" },
    });
    const process = await prepared.start({ policyDigest: prepared.policyDigest, executionDigest: prepared.executionDigest });
    const bytes = Buffer.from([0, 1, 2, 127, 128, 255]);
    process.stdin?.end(bytes);
    const result = await process.wait();
    assert.equal(result.stdout?.equals(bytes), true);
  });
});

test("network-none blocks direct external and host-loopback connections", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const script = [
      "import socket,sys",
      "targets=[('1.1.1.1',80),('127.0.0.1',1),('::1',1)]",
      "for host,port in targets:",
      " s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)",
      " s.settimeout(.2)",
      " try: s.connect((host,port)); sys.exit(9)",
      " except OSError: pass",
      "sys.exit(0)",
    ].join("\n");
    const result = await sandbox.run({
      ...baseOptions(),
      process: { executable: "/usr/bin/python3", args: ["-c", script], cwd: "/" },
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
  });
});

test("network-none hides host abstract Unix sockets", { skip: !linux }, async () => {
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
        `s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)`,
        "s.settimeout(.2)",
        `name=${JSON.stringify(name)}`,
        "try: s.connect(name); sys.exit(9)",
        "except OSError: sys.exit(0)",
      ].join("\n");
      const result = await sandbox.run({
        ...baseOptions(),
        process: { executable: "/usr/bin/python3", args: ["-c", script], cwd: "/" },
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    });
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test("managed networking brokers allowed TCP and reports denied destinations", { skip: !linux }, async () => {
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
    const port = address.port;
    await withSandbox(async (sandbox) => {
      const proxyScript = [
        "import os,socket,urllib.parse",
        `target_port=${port}`,
        "proxy=urllib.parse.urlsplit(os.environ['HTTP_PROXY'])",
        "s=socket.create_connection((proxy.hostname,proxy.port),2)",
        "s.sendall(f'CONNECT 127.0.0.1:{target_port} HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n\\r\\n'.encode())",
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
      const allowed = await sandbox.run({
        ...baseOptions({
          policy: {
            filesystem: { runtime: { kind: "system" }, grants: [] },
            network: {
              mode: "managed",
              allow: [{ transport: "tcp", destination: { kind: "ip", cidr: "127.0.0.1/32" }, ports: [port] }],
            },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: { executable: "/usr/bin/python3", args: ["-c", proxyScript], cwd: "/" },
      });
      assert.deepEqual(allowed.termination, { reason: "exit", code: 0 });
      assert.equal(allowed.usage.networkConnections, 1);

      const denied = await sandbox.run({
        ...baseOptions({
          policy: {
            filesystem: { runtime: { kind: "system" }, grants: [] },
            network: { mode: "managed", allow: [] },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: {
          executable: "/usr/bin/python3",
          args: ["-c", proxyScript.replace("assert b' 200 ' in head,head", "assert b' 200 ' not in head,head; raise SystemExit(0)")],
          cwd: "/",
        },
      });
      assert.deepEqual(denied.termination, { reason: "exit", code: 0 });
      assert.equal(denied.violations.some((violation) => violation.kind === "network-denied"), true);

      const direct = await sandbox.run({
        ...baseOptions({
          policy: {
            filesystem: { runtime: { kind: "system" }, grants: [] },
            network: {
              mode: "managed",
              allow: [{ transport: "tcp", destination: { kind: "ip", cidr: "127.0.0.1/32" }, ports: [port] }],
            },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: {
          executable: "/usr/bin/python3",
          args: ["-c", `import socket; s=socket.socket(); s.settimeout(.2)\ntry: s.connect(('127.0.0.1',${port})); raise SystemExit(9)\nexcept OSError: raise SystemExit(0)`],
          cwd: "/",
        },
      });
      assert.deepEqual(direct.termination, { reason: "exit", code: 0 });
    });
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test("managed networking serves HTTP, SOCKS5 domain/IP, and brokered DNS over UDP/TCP", { skip: !linux }, async () => {
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
    const port = address.port;
    const script = String.raw`
import os,socket,struct,urllib.parse
port=${port}

def read_all(stream):
 data=b''
 while True:
  part=stream.recv(4096)
  if not part: return data
  data+=part

def exact(stream,count):
 data=b''
 while len(data)<count:
  part=stream.recv(count-len(data))
  if not part: raise RuntimeError('unexpected proxy EOF')
  data+=part
 return data

http=urllib.parse.urlsplit(os.environ['HTTP_PROXY'])
s=socket.create_connection((http.hostname,http.port),2)
s.sendall(b'GET http://127.0.0.1:'+str(port).encode()+b'/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
assert read_all(s).endswith(b'ok')

socks=urllib.parse.urlsplit(os.environ['ALL_PROXY'])
for kind in ('ip','domain'):
 s=socket.create_connection((socks.hostname,socks.port),2)
 s.sendall(b'\x05\x01\x00')
 assert exact(s,2)==b'\x05\x00'
 if kind=='ip': request=b'\x05\x01\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',port)
 else:
  host=b'localhost'
  request=b'\x05\x01\x00\x03'+bytes([len(host)])+host+struct.pack('!H',port)
 s.sendall(request)
 head=exact(s,4)
 assert head[1]==0,head
 lengths={1:4,4:16}
 if head[3]==3: exact(s,exact(s,1)[0])
 else: exact(s,lengths[head[3]])
 exact(s,2)
 s.sendall(b'GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
 assert read_all(s).endswith(b'ok')

labels=b''.join(bytes([len(part)])+part for part in b'localhost'.split(b'.'))+b'\x00'
query=struct.pack('!HHHHHH',0x5151,0x0100,1,0,0,0)+labels+struct.pack('!HH',1,1)
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.settimeout(2)
udp.sendto(query,('127.0.0.1',53))
answer=udp.recv(4096)
assert answer[:2]==b'QQ' and answer[3]&15==0 and struct.unpack('!H',answer[6:8])[0]>0
tcp=socket.create_connection(('127.0.0.1',53),2)
tcp.sendall(struct.pack('!H',len(query))+query)
length=struct.unpack('!H',exact(tcp,2))[0]
answer=exact(tcp,length)
assert answer[:2]==b'QQ' and answer[3]&15==0 and struct.unpack('!H',answer[6:8])[0]>0
`;
    await withSandbox(async (sandbox) => {
      const result = await sandbox.run({
        ...baseOptions({
          policy: {
            filesystem: { runtime: { kind: "system" }, grants: [] },
            network: {
              mode: "managed",
              allow: [
                { transport: "tcp", destination: { kind: "ip", cidr: "127.0.0.1/32" }, ports: [port] },
                {
                  transport: "tcp",
                  destination: { kind: "dns", name: "localhost", allowPrivateAddresses: true },
                  ports: [port],
                },
              ],
            },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: { executable: "/usr/bin/python3", args: ["-c", script], cwd: "/" },
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      assert.equal(result.usage.networkConnections, 3);
      assert.equal(result.cleanup.completed, true);
    });
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test("managed broker closes active connections when the target is cancelled", { skip: !linux }, async () => {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("data", () => {});
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    assert.ok(address);
    const port = address.port;
    await withSandbox(async (sandbox) => {
      const script = [
        "import os,socket,urllib.parse",
        "proxy=urllib.parse.urlsplit(os.environ['HTTP_PROXY'])",
        "s=socket.create_connection((proxy.hostname,proxy.port),2)",
        `s.sendall(b'CONNECT 127.0.0.1:${port} HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n\\r\\n')`,
        "assert b' 200 ' in s.recv(4096)",
        "s.sendall(b'GET /hold HTTP/1.1\\r\\nHost: local\\r\\n\\r\\n')",
        "s.recv(1)",
      ].join("\n");
      const result = await sandbox.run({
        ...baseOptions({
          policy: {
            filesystem: { runtime: { kind: "system" }, grants: [] },
            network: {
              mode: "managed",
              allow: [{ transport: "tcp", destination: { kind: "ip", cidr: "127.0.0.1/32" }, ports: [port] }],
            },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
          resources: { wallTimeMs: 400, terminationGraceMs: 50 },
        }),
        process: { executable: "/usr/bin/python3", args: ["-c", script], cwd: "/" },
      });
      assert.deepEqual(result.termination, { reason: "timeout" });
      assert.equal(result.cleanup.completed, true);
      assert.equal(result.usage.networkConnections, 1);
    });
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test("sandboxed processes cannot create nested namespaces", { skip: !linux }, async (context) => {
  try {
    await access("/usr/bin/unshare", constants.X_OK);
  } catch {
    context.skip("unshare is not installed on this host");
    return;
  }
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: {
        executable: "/usr/bin/unshare",
        args: ["--user", "--map-root-user", "/bin/true"],
        cwd: "/",
      },
    });
    assert.equal(result.termination.reason, "exit");
    assert.notEqual(result.termination.code, 0);
  });
});

test("wall time continues while output is backpressured", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions({ resources: { wallTimeMs: 100 } }),
      process: { executable: "/bin/sh", args: ["-c", "yes blocked"], cwd: "/", stdout: "pipe" },
    });
    const process = await prepared.start({ policyDigest: prepared.policyDigest, executionDigest: prepared.executionDigest });
    const result = await process.wait();
    assert.deepEqual(result.termination, { reason: "timeout" });
  });
});

test("a target that never reads stdin cannot block its timeout", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions({ resources: { wallTimeMs: 100 } }),
      process: { executable: "/bin/sh", args: ["-c", "sleep 10"], cwd: "/", stdin: "pipe" },
    });
    const process = await prepared.start({ policyDigest: prepared.policyDigest, executionDigest: prepared.executionDigest });
    process.stdin?.write(Buffer.alloc(1024 * 1024));
    const result = await process.wait();
    assert.deepEqual(result.termination, { reason: "timeout" });
  });
});

test("output limit is counted before delivery and terminates the tree", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions({ resources: { maxOutputBytes: 1000 } }),
      process: { executable: "/bin/sh", args: ["-c", "yes x"], cwd: "/" },
    });
    assert.deepEqual(result.termination, { reason: "output-limit" });
    assert.equal(result.stdout?.byteLength, 1000);
    assert.equal((result.usage.stdoutBytes + result.usage.stderrBytes) > 1000, true);
  });
});

test("CPU and single-file limits retain structured attribution", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const cpu = await sandbox.run({
      ...baseOptions({ resources: { wallTimeMs: 5_000, cpuTimeMs: 1_000 } }),
      process: { executable: "/bin/sh", args: ["-c", "while :; do :; done"], cwd: "/" },
    });
    assert.deepEqual(cpu.termination, { reason: "cpu-limit" });

    const file = await sandbox.run({
      ...baseOptions({ resources: { maxSingleFileBytes: 1_024 } }),
      process: {
        executable: "/bin/dd",
        args: ["if=/dev/zero", "of=/tmp/large", "bs=4096", "count=1"],
        cwd: "/",
      },
    });
    assert.deepEqual(file.termination, { reason: "single-file-size-limit" });
  });
});

test("delegated cgroup exhaustion is attributed to memory and process limits", { skip: !linux }, async (context) => {
  await withSandbox(async (sandbox) => {
    const support = await sandbox.probe();
    const backend = support.backends.find((candidate) => candidate.id === "linux-namespace-v1");
    if (backend?.capabilities.cgroupMemory !== true || backend.capabilities.cgroupProcesses !== true) {
      context.skip("host has no functionally verified cgroup v2 delegation");
      return;
    }
    const memory = await sandbox.run({
      ...baseOptions({ resources: { memoryBytes: 32 * 1024 * 1024, wallTimeMs: 10_000 } }),
      process: {
        executable: "/usr/bin/python3",
        args: ["-c", "x=bytearray(256*1024*1024); print(len(x))"],
        cwd: "/",
      },
    });
    assert.deepEqual(memory.termination, { reason: "memory-limit" });

    const processes = await sandbox.run({
      ...baseOptions({ resources: { maxProcesses: 2, wallTimeMs: 5_000 } }),
      process: {
        executable: "/bin/sh",
        args: ["-c", "for i in 1 2 3 4 5 6; do sleep 1 & done; wait"],
        cwd: "/",
      },
    });
    assert.deepEqual(processes.termination, { reason: "process-limit" });
  });
});

test("normal exit cannot leave daemonized descendants", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-tree-"));
  try {
    await withSandbox(async (sandbox) => {
      const result = await sandbox.run({
        ...baseOptions({
          policy: {
            filesystem: {
              runtime: { kind: "system" },
              grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read-write" }],
            },
            network: { mode: "none" },
            process: { hostProcesses: "deny", hostIpc: "deny" },
          },
        }),
        process: {
          executable: "/bin/sh",
          args: ["-c", "(sleep .5; echo escaped > /workspace/escaped) & exit 0"],
          cwd: "/workspace",
        },
      });
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 700));
      await assert.rejects(access(join(workspace, "escaped"), constants.F_OK));
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("sessions retain immutable authority and run sequential processes", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareSession(baseOptions());
    const session = await prepared.activate({ policyDigest: prepared.policyDigest });
    try {
      const first = await session.run({ executable: "/bin/printf", args: ["one"], cwd: "/" });
      const second = await session.run({ executable: "/bin/printf", args: ["two"], cwd: "/" });
      assert.equal(first.stdout?.toString(), "one");
      assert.equal(second.stdout?.toString(), "two");
    } finally {
      await session.close();
      await session.close();
    }
  });
});

test("ordinary permission text is not classified as a structured violation", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: { executable: "/bin/sh", args: ["-c", "echo permission denied >&2; exit 7"], cwd: "/" },
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 7 });
    assert.equal(result.stderr?.toString().trim(), "permission denied");
    assert.deepEqual(result.violations, []);
  });
});

test("raw target signals retain structured attribution", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const result = await sandbox.run({
      ...baseOptions(),
      process: { executable: "/bin/sh", args: ["-c", "kill -TERM $$"], cwd: "/" },
    });
    assert.deepEqual(result.termination, { reason: "signal", signal: "SIGTERM" });
    assert.equal(result.cleanup.completed, true);
  });
});

test("process identities do not mislabel the launcher as the workload", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions(),
      process: { executable: "/bin/true", cwd: "/" },
    });
    const process = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
    assert.deepEqual(process.identity, { kind: "opaque" });
    await process.wait();
  });
});

test("SIGKILL of the Rust supervisor cannot orphan the launcher tree", { skip: !linux }, async () => {
  const before = new Set(await directChildren(process.pid));
  const sandbox = await createSandbox();
  try {
    const prepared = await sandbox.prepareRun({
      ...baseOptions({ resources: { wallTimeMs: 30_000 } }),
      process: { executable: "/bin/sh", args: ["-c", "sleep 30"], cwd: "/" },
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
    }, 5_000);
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
