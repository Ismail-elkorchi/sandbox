export type SandboxEnvironmentValue =
  | string
  | { value: string; sensitive: true };

export interface SandboxEnvironment {
  base?: "minimal" | "empty";
  inherit?: readonly string[];
  set?: Readonly<Record<string, SandboxEnvironmentValue>>;
  unset?: readonly string[];
}
