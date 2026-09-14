import { registerHooks } from "node:module";

const sandbox = new URL("../../dist/sandbox.js", import.meta.url).href;
registerHooks({
  load(url, context, nextLoad) {
    if (url === sandbox) return {
      format: "module", shortCircuit: true,
      source: 'export async function createSandbox() { throw new Error("Injected runtime initialization failure"); }',
    };
    return nextLoad(url, context);
  },
});
await import("../../dist/execution-worker.js");
