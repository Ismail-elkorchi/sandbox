export type ResourceLimitScope = "process" | "descendant-tree" | "session";

export interface HardLimit<Scope extends ResourceLimitScope = ResourceLimitScope> {
  enforcement: "hard";
  scope: Scope;
  value: number;
}

/** Aggregate memory, process-count, and CPU limits are enforced only when requested. */
export interface ResourceLimits {
  wallTime?: HardLimit<"process" | "session">;
  cpuTime?: HardLimit<"descendant-tree" | "session">;
  memory?: HardLimit<"descendant-tree" | "session">;
  processCount?: HardLimit<"descendant-tree" | "session">;
  openFiles?: HardLimit<"process">;
  singleFileSize?: HardLimit<"process">;
  output?: HardLimit<"process" | "session">;
}

export interface ResolvedResourceLimits {
  wallTime: HardLimit<"process" | "session">;
  cpuTime?: HardLimit<"descendant-tree" | "session">;
  memory?: HardLimit<"descendant-tree" | "session">;
  processCount?: HardLimit<"descendant-tree" | "session">;
  openFiles?: HardLimit<"process">;
  singleFileSize?: HardLimit<"process">;
  output: HardLimit<"process" | "session">;
}
