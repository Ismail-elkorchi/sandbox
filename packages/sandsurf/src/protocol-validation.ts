import { protocolShapes, type ProtocolTypes } from "./protocol-generated.js";

/** Structural wire validation only. Domain owners still check cross-field
 * semantics, digests, authority, generation and byte-retention coverage. */
export function validateProtocol<K extends keyof ProtocolTypes>(name: K, value: unknown): asserts value is ProtocolTypes[K] {
  let remaining = 262144;
  const check = (shape: readonly unknown[], value: unknown, parameters: readonly (readonly unknown[])[], depth: number): boolean => {
    if (--remaining < 0 || depth > 64) return false;
    const nested = (shape: readonly unknown[], value: unknown): boolean => check(shape, value, parameters, depth + 1);
    const object = (item: unknown): item is Record<string, unknown> => item !== null && typeof item === "object" && !Array.isArray(item);
    switch (shape[0]) {
      case "string": return typeof value === "string";
      case "boolean": return typeof value === "boolean";
      case "integer": return typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= (shape[1] as number) && value <= (shape[2] as number);
      case "null": return value === null;
      case "literal": return value === shape[1];
      case "parameter": return nested(parameters[shape[1] as number]!, value);
      case "reference": {
        const definition = protocolShapes[shape[1] as string];
        if (definition === undefined) throw new Error("undefined generated wire type");
        const arguments_ = (shape[2] as readonly (readonly unknown[])[]).map((arg) => arg[0] === "parameter" ? parameters[arg[1] as number]! : arg);
        return check(definition, value, arguments_, depth + 1);
      }
      case "array": {
        if (!Array.isArray(value) || value.length > remaining || (shape[2] !== undefined && value.length !== shape[2])) return false;
        const element = shape[1] as readonly unknown[];
        // Dense binary control placeholders and byte paths need no recursive
        // dispatch or per-byte closure allocation. Charge the same node budget.
        if (element[0] === "integer") {
          remaining -= value.length;
          for (const item of value) {
            if (typeof item !== "number" || !Number.isSafeInteger(item) || Object.is(item, -0) || item < (element[1] as number) || item > (element[2] as number)) return false;
          }
          return true;
        }
        // Array.every skips holes. A hole must not become a valid byte or an
        // implicitly nullable field during subsequent JSON/binary encoding.
        for (const item of value) if (!nested(element, item)) return false;
        return true;
      }
      case "map": return object(value) && Object.keys(value).length <= remaining && Object.values(value).every((item) => nested(shape[1] as readonly unknown[], item));
      case "object": {
        if (!object(value)) return false;
        const fields = shape[1] as Readonly<Record<string, readonly unknown[]>>;
        const keys = Object.keys(value);
        return keys.length === Object.keys(fields).length && keys.every((key) => Object.hasOwn(fields, key) && nested(fields[key]!, value[key]));
      }
      case "union": return (shape[1] as readonly (readonly unknown[])[]).some((variant) => nested(variant, value));
      default: throw new Error("unknown generated wire shape");
    }
  };
  if (!check(protocolShapes[name]!, value, [], 0)) throw new Error(`invalid Sandsurf ${name} wire shape`);
}
