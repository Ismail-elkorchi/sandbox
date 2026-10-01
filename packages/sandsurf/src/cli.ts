#!/usr/bin/env node
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { resolveSandsurfNativeHost } from "./native-host.js";
import { Sandsurf, type HostInspection } from "./sandsurf.js";
import {
  sandsurfServiceDefinition,
  type SandsurfServicePlatform,
} from "./service.js";

export async function main(arguments_: readonly string[]): Promise<number> {
  const [command, ...argumentsRest] = arguments_;
  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(help());
    return 0;
  }
  const options = parse(argumentsRest);
  if (command === "storage-path" || command === "storage-volume") {
    if (command === "storage-path" && options.machine === undefined) throw new TypeError("storage-path requires --machine");
    const binary = await resolveSandsurfNativeHost();
    return new Promise<number>((resolveRun, rejectRun) => {
      execFile(binary, [command, "--directory", options.directory, ...(options.machine === undefined ? [] : ["--machine", options.machine])],
        { timeout: 10_000, maxBuffer: 16 * 1024 }, (error, stdout, stderr) => {
          process.stdout.write(stdout); process.stderr.write(stderr);
          if (error === null) resolveRun(0);
          else if (error.code === 2) resolveRun(2);
          else rejectRun(error);
        });
    });
  }
  if (command === "qualify") {
    const host = await Sandsurf.open({ directory: options.directory });
    try {
      const inspection = await host.inspect();
      process.stdout.write(
        options.json ? `${JSON.stringify(inspection, null, 2)}\n` : qualificationText(inspection),
      );
      return inspection.lifecycle.kind === "qualified" && inspection.images.kind === "qualified"
        ? 0
        : 2;
    } finally {
      await host.close();
    }
  }
  if (command === "setup") {
    const definition = await sandsurfServiceDefinition({
      directory: options.directory,
      ...(options.platform === undefined ? {} : { platform: options.platform }),
    });
    process.stdout.write(
      options.json
        ? `${JSON.stringify(definition, null, 2)}\n`
        : `${definition.files.map((file) => `# ${file.name}\n${file.contents}`).join("\n")}\n# ${definition.installHint}\n`,
    );
    return 0;
  }
  throw new TypeError(`Unknown Sandsurf command: ${command}`);
}

function parse(arguments_: readonly string[]): {
  readonly directory: string;
  readonly json: boolean;
  readonly platform?: SandsurfServicePlatform;
  readonly machine?: string;
} {
  let directory: string | undefined;
  let json = false;
  let platform: SandsurfServicePlatform | undefined;
  let machine: string | undefined;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--json") json = true;
    else if (argument === "--directory") directory = requiredValue(arguments_, ++index, argument);
    else if (argument === "--machine") {
      machine = requiredValue(arguments_, ++index, argument);
      if (!/^[A-Za-z0-9_-]{1,128}$/u.test(machine)) throw new TypeError("invalid machine identity");
    }
    else if (argument === "--platform") {
      const supplied = requiredValue(arguments_, ++index, argument);
      if (supplied !== "linux" && supplied !== "macos" && supplied !== "windows")
        throw new TypeError("--platform must be linux, macos, or windows");
      platform = supplied;
    } else throw new TypeError(`Unknown Sandsurf option: ${String(argument)}`);
  }
  if (directory === undefined) throw new TypeError("--directory is required");
  return {
    directory: resolve(directory),
    json,
    ...(platform === undefined ? {} : { platform }),
    ...(machine === undefined ? {} : { machine }),
  };
}

function requiredValue(arguments_: readonly string[], index: number, option: string): string {
  const value = arguments_[index];
  if (value === undefined || value.startsWith("--"))
    throw new TypeError(`${option} requires a value`);
  return value;
}

function qualificationText(inspection: HostInspection): string {
  const line = (name: string, value: HostInspection["lifecycle"]): string =>
    value.kind === "qualified"
      ? `${name}: qualified (${value.evidence})`
      : `${name}: unqualified (${value.reasons.join("; ")})`;
  return [
    `host: ${inspection.hostId}`,
    `engine: ${inspection.engine} (${inspection.platform}/${inspection.architecture} -> ${inspection.guestPlatform})`,
    line("lifecycle", inspection.lifecycle),
    line("images", inspection.images),
    line("full-state", inspection.fullState),
    "",
  ].join("\n");
}

function help(): string {
  return "Usage:\n  sandsurf qualify --directory <absolute-state-directory> [--json]\n  sandsurf setup --directory <absolute-state-directory> [--platform linux|macos|windows] [--json]\n  sandsurf storage-path --directory <absolute-state-directory> --machine <identity>\n  sandsurf storage-volume --directory <absolute-state-directory> [--machine <identity>]\n\nsetup renders explicit service definitions; storage commands locate or inspect operator volumes. Neither installs services, mounts volumes or enables privileged features.\n";
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    },
  );
}
