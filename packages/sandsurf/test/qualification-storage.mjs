import { realpath } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

// Hardware fixtures use operator-mounted volumes, not unbounded mkdtemp
// directories. They never mount, resize, recycle, or erase retained evidence.
export async function qualificationDirectory(name) {
  const root = process.env.SANDSURF_QUALIFICATION_ROOT;
  if (root === undefined || !isAbsolute(root)) throw new Error("provision bounded qualification volumes and set SANDSURF_QUALIFICATION_ROOT to their absolute parent");
  const path = join(root, name);
  if (await realpath(path) !== path) throw new Error("qualification storage must be canonical");
  return path;
}
