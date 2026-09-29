import { writeImageIndex } from "./image-sources.ts";

const required = new Set(
  (process.env.SANDSURF_REQUIRED_IMAGE_ARCHITECTURES ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0),
);
await writeImageIndex(undefined, [...required]);
