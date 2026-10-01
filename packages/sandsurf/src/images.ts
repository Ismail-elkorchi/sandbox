import type { ImageImportOptions, ImageInspection, ImageReleaseInspection, NativeImageImportOptions } from "./contracts.js";
import { record, text } from "./native-host.js";
import { normalizeOciSource, parseImage } from "./observations.js";
import type { Sandsurf } from "./sandsurf.js";
import { authorize, digest, identity, protocol, transport, validateIdentity } from "./sdk-internal.js";
import { isAbsolute } from "node:path";

export class ImageCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async importNative(options: NativeImageImportOptions): Promise<Image> {
    if (typeof options.manifestPath !== "string" || !isAbsolute(options.manifestPath) || options.manifestPath.includes("\0")) throw new TypeError("native image manifest path must be absolute");
    const manifestDigest = digest(options.manifestDigest);
    const operationId = validateIdentity(options.operationId ?? identity("image"));
    const request = { manifestPath: options.manifestPath, manifestDigest };
    const approvalId = await this.#host[authorize]({ kind: "image-import", machineId: "host", operationId, request });
    const response = await this.#host[transport]({ kind: "import-native-image", ...request, operationId, approvalId });
    if (response.kind !== "image-import" || !record(response.operation) || !record(response.operation.image)) throw protocol("native image import response");
    const image = parseImage(response.operation.image);
    if (image.digest !== manifestDigest) throw protocol("native image import identity");
    return new Image(image);
  }
  async importOCI(options: ImageImportOptions): Promise<Image> {
    const operationId = validateIdentity(options.operationId ?? identity("image"));
    if (!record(options.recipe)) throw new TypeError("OCI conversion requires an explicit machine-image recipe");
    const recipe = { bootImageDigest: digest(typeof options.recipe.bootImage === "string" ? options.recipe.bootImage : options.recipe.bootImage.id) };
    const platform = options.platform ?? (await this.#host.inspect()).guestPlatform;
    const source = normalizeOciSource(options);
    const approvalId = await this.#host[authorize]({ kind: "image-import", machineId: "host", operationId, request: { source, recipe, platform } });
    const response = await this.#host[transport]({ kind: "import-oci", source, recipe, platform, operationId, approvalId });
    if (response.kind !== "image-import" || !record(response.operation) || !record(response.operation.image)) throw protocol("image import response");
    return new Image(parseImage(response.operation.image));
  }
  async get(digestValue: string): Promise<Image> {
    const response = await this.#host[transport]({ kind: "get-image", digest: digest(digestValue) });
    if (response.kind !== "image" || !record(response.value)) throw protocol("image response");
    return new Image(parseImage(response.value));
  }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly Image[]> {
    const response = await this.#host[transport]({ kind: "list-images", after: options.after === undefined ? null : digest(options.after), maximum: options.maximum ?? 100 });
    if (response.kind !== "images" || !Array.isArray(response.values)) throw protocol("image list response");
    return response.values.map((value) => new Image(parseImage(value)));
  }
  async release(image: string | Image, options: { readonly operationId?: string } = {}): Promise<ImageReleaseInspection> {
    const imageDigest = digest(typeof image === "string" ? image : image.id); const operationId = validateIdentity(options.operationId ?? identity("release-image"));
    const approvalId = await this.#host[authorize]({ kind: "image-release", machineId: "host", operationId, request: { imageDigest } });
    const response = await this.#host[transport]({ kind: "release-image", digest: imageDigest, operationId, approvalId });
    if (response.kind !== "image-release" || !record(response.operation)) throw protocol("image release response");
    return { operationId: text(response.operation.operationId), imageDigest: digest(text(response.operation.imageDigest)), requestDigest: digest(text(response.operation.requestDigest)), cleanupPending: response.operation.cleanupPending === true };
  }
}

export class Image {
  readonly id: string;
  readonly inspection: ImageInspection;
  constructor(inspection: ImageInspection) { this.id = inspection.digest; this.inspection = inspection; }
}
