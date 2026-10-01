import { resolve } from "node:path";
import { packageArchive } from "./package-archive.ts";

const npmCli = process.env.npm_execpath;
if (npmCli === undefined) throw new Error("npm_execpath is required for package creation");
console.log(await packageArchive(resolve("packages/sandsurf"), resolve("release"), npmCli));
