import { createHash } from "node:crypto";
import { posix, resolve, win32 } from "node:path";
import { resolveSandsurfNativeHost } from "./native-host.js";

export type SandsurfServicePlatform = "linux" | "macos" | "windows";

export interface SandsurfServiceDefinition {
  readonly platform: SandsurfServicePlatform;
  readonly format: "systemd-user" | "launchd-agent" | "windows-scm-powershell";
  readonly files: readonly { readonly name: string; readonly contents: string }[];
  readonly installHint: string;
}

export interface SandsurfServiceDefinitionOptions {
  readonly directory: string;
  readonly binary?: string;
  readonly platform?: SandsurfServicePlatform;
}

/** Render independent host API and guardian supervision services. No install. */
export async function sandsurfServiceDefinition(options: SandsurfServiceDefinitionOptions): Promise<SandsurfServiceDefinition> {
  return renderSandsurfServiceDefinition({
    directory: resolve(options.directory),
    binary: options.binary === undefined ? await resolveSandsurfNativeHost() : resolve(options.binary),
    platform: options.platform ?? currentPlatform(),
  });
}

export function renderSandsurfServiceDefinition(options: {
  readonly directory: string; readonly binary: string; readonly platform: SandsurfServicePlatform;
}): SandsurfServiceDefinition {
  const path = options.platform === "windows" ? win32 : posix;
  for (const value of [options.directory, options.binary]) {
    if (!path.isAbsolute(value) || /[\u0000-\u001f\u007f]/u.test(value)) throw new TypeError("Sandsurf service paths must be absolute without control characters");
  }
  const directoryDigest = createHash("sha256").update(options.directory).digest("hex");
  const suffix = directoryDigest.slice(0, 12);
  const host = options.platform === "linux" ? `sandsurf-api-id-${directoryDigest}` : `sandsurf-host-${suffix}`;
  const supervisor = options.platform === "linux" ? `sandsurf-supervisor-id-${directoryDigest}` : `sandsurf-supervisor-${suffix}`;
  const file = (name: string, contents: string): Readonly<{ name: string; contents: string }> => Object.freeze({ name, contents });
  switch (options.platform) {
    case "linux": {
      const unit = (name: string, mode: string, dependency: string): string =>
        // These authority services share the client's authorized host paths.
        // Per-unit PrivateTmp would create different stores at the same name.
        // Guest/VMM isolation belongs to the qualified native launcher instead.
        `[Unit]\nDescription=Sandsurf ${name}\nAfter=network.target${dependency === "" ? "" : ` ${dependency}.service`}\n${dependency === "" ? "" : `Wants=${dependency}.service\n`}\n[Service]\nType=exec\nExecStart=${systemdArgument(options.binary)} ${mode} --directory ${systemdArgument(options.directory)}\nRestart=on-failure\nRestartSec=1\nNoNewPrivileges=true\nCPUQuota=100%\nCPUQuotaPeriodSec=100ms\nMemoryMax=${mode === "serve" ? 536870912 : 134217728}\nMemorySwapMax=0\nOOMPolicy=kill\nTasksMax=${mode === "serve" ? 256 : 64}\nKillMode=control-group\nDelegate=no\n\n[Install]\nWantedBy=default.target\n`;
      return Object.freeze({ platform: "linux", format: "systemd-user",
        files: Object.freeze([file(`${supervisor}.service`, unit("guardian supervision", "supervise", "")), file(`${host}.service`, unit("host API", "serve", supervisor))]),
        installHint: `Write both units to ~/.config/systemd/user/, then run systemctl --user daemon-reload and systemctl --user enable --now ${supervisor}.service ${host}.service. Keep the account's user manager running for unattended work. Restarting the host API unit does not stop the supervisor unit or its guardians.`,
      });
    }
    case "macos": {
      const agent = (role: string, mode: string): Readonly<{ name: string; contents: string }> => {
        const label = `dev.sandsurf.${role}.${suffix}`;
        return file(`${label}.plist`, `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n<key>Label</key><string>${label}</string>\n<key>ProgramArguments</key><array><string>${xml(options.binary)}</string><string>${mode}</string><string>--directory</string><string>${xml(options.directory)}</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ProcessType</key><string>Interactive</string>\n</dict></plist>\n`);
      };
      return Object.freeze({ platform: "macos", format: "launchd-agent", files: Object.freeze([agent("supervisor", "supervise"), agent("host", "serve")]),
        installHint: "Write both plists to ~/Library/LaunchAgents/ and bootstrap each with launchctl in the account's GUI domain. The VM owner still needs its Apple virtualization entitlement/signature and real-hardware qualification. A GUI LaunchAgent does not promise survival of account logout.",
      });
    }
    case "windows": {
      if (options.binary.includes('"') || options.directory.includes('"')) throw new TypeError("Windows service paths cannot contain quotes");
      const command = (role: string, name: string): string => powershell(`\"${options.binary}\" service --directory \"${options.directory}\" --service-name \"${name}\" --role ${role}`);
      return Object.freeze({ platform: "windows", format: "windows-scm-powershell", files: Object.freeze([file(`${host}.ps1`,
        `$serviceUser = \"$env:USERDOMAIN\\$env:USERNAME\"\n$credential = Get-Credential -UserName $serviceUser -Message 'Account for Sandsurf services'\nNew-Item -ItemType Directory -Force -Path '${powershell(options.directory)}' | Out-Null\nicacls '${powershell(options.directory)}' /inheritance:r /grant:r \"$($serviceUser):(OI)(CI)F\" 'SYSTEM:(OI)(CI)F' | Out-Null\nNew-Service -Name '${supervisor}' -BinaryPathName '${command("supervisor", supervisor)}' -Credential $credential -StartupType Automatic\nNew-Service -Name '${host}' -BinaryPathName '${command("host", host)}' -Credential $credential -DependsOn '${supervisor}' -StartupType Automatic\nStart-Service -Name '${supervisor}'\nStart-Service -Name '${host}'\n`)]),
        installHint: "Run the PowerShell definition from an elevated shell after enabling and rebooting into Hyper-V. Both independent services use the chosen unprivileged account, which needs Log on as a service and access to the qualified HCS implementation. Stopping the host API service does not stop guardian supervision.",
      });
    }
  }
}

function currentPlatform(): SandsurfServicePlatform {
  if (process.platform === "linux") return "linux";
  if (process.platform === "darwin") return "macos";
  if (process.platform === "win32") return "windows";
  throw new TypeError(`Sandsurf has no service definition for ${process.platform}`);
}
function systemdArgument(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("%", "%%").replaceAll("$", () => "$$")}"`;
}
function xml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
}
function powershell(value: string): string { return value.replaceAll("'", "''"); }
