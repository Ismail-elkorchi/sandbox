//! Source-derived wire types. Unsupported serde shapes fail the build rather
//! than silently producing a second, weaker version of the protocol.
#![deny(unsafe_code)]
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt::Write as _};
use syn::{Attribute, Fields, GenericArgument, Item, LitStr, PathArguments, Type};

const SOURCES: &[&str] = &[
    include_str!("../types.rs"),
    include_str!("../guest.rs"),
    include_str!("../environment.rs"),
    include_str!("../snapshot.rs"),
    include_str!("../console.rs"),
    include_str!("../binary.rs"),
    include_str!("../session.rs"),
];

#[derive(Default)]
struct Serde {
    rename: Option<String>,
    fields: Option<String>,
    tag: Option<String>,
    from: Option<String>,
}

fn attributes(attrs: &[Attribute]) -> Serde {
    let mut result = Serde::default();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("serde")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("deny_unknown_fields") {
                return Ok(());
            }
            if ![
                "rename_all",
                "rename",
                "rename_all_fields",
                "tag",
                "try_from",
                "into",
            ]
            .iter()
            .any(|name| meta.path.is_ident(name))
            {
                return Err(meta.error("unsupported serde attribute in TypeScript contract"));
            }
            let value = meta.value()?.parse::<LitStr>()?.value();
            let slot = if meta.path.is_ident("rename_all") || meta.path.is_ident("rename") {
                &mut result.rename
            } else if meta.path.is_ident("rename_all_fields") {
                &mut result.fields
            } else if meta.path.is_ident("tag") {
                &mut result.tag
            } else if meta.path.is_ident("try_from") {
                &mut result.from
            } else if meta.path.is_ident("into") {
                return Ok(());
            } else {
                return Err(meta.error("unsupported serde attribute in TypeScript contract"));
            };
            assert!(
                slot.replace(value).is_none(),
                "conflicting serde attributes"
            );
            Ok(())
        })
        .expect("supported serde contract");
    }
    result
}

fn renamed(name: &str, style: Option<&str>) -> String {
    match style {
        None => name.into(),
        Some("camelCase") => {
            let mut output = String::new();
            let mut upper = false;
            for ch in name.chars() {
                if ch == '_' {
                    upper = true;
                } else if upper {
                    output.extend(ch.to_uppercase());
                    upper = false;
                } else {
                    output.push(ch);
                }
            }
            output
        }
        Some("kebab-case") => {
            let mut output = String::new();
            for (index, ch) in name.chars().enumerate() {
                if index != 0 && ch.is_uppercase() {
                    output.push('-');
                }
                output.extend(ch.to_lowercase());
            }
            output
        }
        Some(other) => panic!("unsupported serde rename style: {other}"),
    }
}

fn shape(ty: &Type, parameters: &[String]) -> Value {
    if let Type::Array(array) = ty {
        let syn::Expr::Lit(length) = &array.len else {
            panic!("literal wire array length required")
        };
        let syn::Lit::Int(length) = &length.lit else {
            panic!("integer wire array length required")
        };
        return json!([
            "array",
            shape(&array.elem, parameters),
            length.base10_parse::<usize>().expect("array length")
        ]);
    }
    let Type::Path(path) = ty else {
        panic!("unsupported wire type");
    };
    let last = path.path.segments.last().expect("type path");
    let name = last.ident.to_string();
    let arguments = match &last.arguments {
        PathArguments::None => Vec::new(),
        PathArguments::AngleBracketed(args) => args
            .args
            .iter()
            .map(|arg| match arg {
                GenericArgument::Type(ty) => shape(ty, parameters),
                _ => panic!("unsupported wire generic argument"),
            })
            .collect::<Vec<_>>(),
        _ => panic!("unsupported wire generic arguments"),
    };
    if let Some(index) = parameters.iter().position(|param| param == &name) {
        return json!(["parameter", index]);
    }
    match name.as_str() {
        "String" => json!(["string"]),
        "bool" => json!(["boolean"]),
        "u8" => json!(["integer", 0, 255]),
        "u16" => json!(["integer", 0, 65535]),
        "u32" => json!(["integer", 0, u32::MAX]),
        "u64" | "usize" => json!(["integer", 0, sandsurf_protocol::Counter::MAX]),
        "i32" => json!(["integer", i32::MIN, i32::MAX]),
        "Option" => json!(["union", [["null"], arguments[0]]]),
        "Vec" => json!(["array", arguments[0]]),
        "Box" => arguments[0].clone(),
        "BTreeMap" => {
            assert_eq!(arguments[0], json!(["string"]), "string map keys required");
            json!(["map", arguments[1]])
        }
        _ => json!(["reference", name, arguments]),
    }
}

fn fields(fields: &Fields, style: Option<&str>, params: &[String]) -> Value {
    let Fields::Named(fields) = fields else {
        panic!("named wire fields required");
    };
    let mut properties = serde_json::Map::new();
    for field in &fields.named {
        let attrs = attributes(&field.attrs);
        assert!(attrs.tag.is_none() && attrs.from.is_none() && attrs.fields.is_none());
        let name = field.ident.as_ref().expect("named field").to_string();
        let name = attrs.rename.unwrap_or_else(|| renamed(&name, style));
        assert!(properties.insert(name, shape(&field.ty, params)).is_none());
    }
    json!(["object", properties])
}

fn definitions(sources: &[&str]) -> BTreeMap<String, (Vec<String>, Value)> {
    let mut result = BTreeMap::new();
    for source in sources {
        for item in syn::parse_file(source).expect("valid Rust source").items {
            let (name, params, schema) = match item {
                Item::Struct(item) if item.attrs.iter().any(|a| a.path().is_ident("serde")) => {
                    let attrs = attributes(&item.attrs);
                    let params = item
                        .generics
                        .type_params()
                        .map(|p| p.ident.to_string())
                        .collect::<Vec<_>>();
                    let schema = if let Some(from) = attrs.from {
                        shape(
                            &syn::parse_str::<Type>(&from).expect("serde conversion type"),
                            &params,
                        )
                    } else {
                        assert!(attrs.tag.is_none() && attrs.fields.is_none());
                        fields(&item.fields, attrs.rename.as_deref(), &params)
                    };
                    (item.ident.to_string(), params, schema)
                }
                Item::Enum(item) if item.attrs.iter().any(|a| a.path().is_ident("serde")) => {
                    let attrs = attributes(&item.attrs);
                    let params = item
                        .generics
                        .type_params()
                        .map(|p| p.ident.to_string())
                        .collect::<Vec<_>>();
                    let variants = item
                        .variants
                        .iter()
                        .map(|variant| {
                            let own = attributes(&variant.attrs);
                            let name = own.rename.unwrap_or_else(|| {
                                renamed(&variant.ident.to_string(), attrs.rename.as_deref())
                            });
                            match (&attrs.tag, &variant.fields) {
                                (None, Fields::Unit) => json!(["literal", name]),
                                (Some(tag), Fields::Unit) => {
                                    json!(["object", {tag: ["literal", name]}])
                                }
                                (Some(tag), Fields::Named(_)) => {
                                    let mut schema =
                                        fields(&variant.fields, attrs.fields.as_deref(), &params);
                                    assert!(
                                        schema[1]
                                            .as_object_mut()
                                            .expect("properties")
                                            .insert(tag.clone(), json!(["literal", name]))
                                            .is_none()
                                    );
                                    schema
                                }
                                (Some(tag), Fields::Unnamed(value)) if value.unnamed.len() == 1 => {
                                    json!([
                                        "tagged",
                                        tag,
                                        name,
                                        shape(&value.unnamed[0].ty, &params)
                                    ])
                                }
                                _ => panic!("unsupported serde enum shape"),
                            }
                        })
                        .collect::<Vec<_>>();
                    (item.ident.to_string(), params, json!(["union", variants]))
                }
                Item::Macro(item) if item.mac.path.is_ident("identifier") => {
                    let names = item.mac.parse_body_with(syn::punctuated::Punctuated::<syn::Ident, syn::Token![,]>::parse_terminated).expect("identifier names");
                    for name in names {
                        assert!(
                            result
                                .insert(name.to_string(), (Vec::new(), json!(["string"])))
                                .is_none()
                        );
                    }
                    continue;
                }
                Item::Macro(item) if item.mac.path.is_ident("lowercase_hex") => {
                    let name = item
                        .mac
                        .parse_body_with(|input: syn::parse::ParseStream<'_>| {
                            let name: syn::Ident = input.parse()?;
                            input.parse::<syn::Token![,]>()?;
                            input.parse::<syn::LitInt>()?;
                            input.parse::<syn::Token![,]>()?;
                            input.parse::<LitStr>()?;
                            Ok(name)
                        })
                        .expect("hex wrapper");
                    (name.to_string(), Vec::new(), json!(["string"]))
                }
                _ => continue,
            };
            assert!(
                result.insert(name, (params, schema)).is_none(),
                "duplicate wire type"
            );
        }
    }
    // Resolve tagged newtypes into their serialized fields, not a fictitious
    // content property. Current contracts only flatten named non-generic types.
    let unresolved = result.clone();
    for (_, schema) in result.values_mut() {
        resolve(schema, &unresolved);
    }
    result
}

fn resolve(schema: &mut Value, definitions: &BTreeMap<String, (Vec<String>, Value)>) {
    if schema[0] == "reference" {
        let name = schema[1].as_str().expect("reference");
        let (params, _) = definitions
            .get(name)
            .unwrap_or_else(|| panic!("undefined wire type: {name}"));
        assert_eq!(params.len(), schema[2].as_array().expect("arguments").len());
    }
    if schema[0] == "tagged" {
        let tag = schema[1].as_str().expect("tag").to_owned();
        let name = schema[2].as_str().expect("variant").to_owned();
        let reference = &schema[3];
        assert_eq!(reference[0], "reference");
        assert!(reference[2].as_array().expect("arguments").is_empty());
        *schema = definitions[reference[1].as_str().expect("reference")]
            .1
            .clone();
        assert_eq!(
            schema[0], "object",
            "tagged newtype must serialize named fields"
        );
        assert!(
            schema[1]
                .as_object_mut()
                .expect("fields")
                .insert(tag, json!(["literal", name]))
                .is_none()
        );
    }
    match schema[0].as_str().expect("shape") {
        "object" => {
            for field in schema[1].as_object_mut().expect("fields").values_mut() {
                resolve(field, definitions);
            }
        }
        "union" => {
            for variant in schema[1].as_array_mut().expect("variants") {
                resolve(variant, definitions);
            }
        }
        "array" | "map" => resolve(&mut schema[1], definitions),
        "reference" => {
            for arg in schema[2].as_array_mut().expect("arguments") {
                resolve(arg, definitions);
            }
        }
        _ => {}
    }
}

fn typescript(schema: &Value, parameters: &[String]) -> String {
    match schema[0].as_str().expect("shape") {
        "string" => "string".into(),
        "boolean" => "boolean".into(),
        "integer" => "number".into(),
        "null" => "null".into(),
        "literal" => schema[1].to_string(),
        "parameter" => parameters[schema[1].as_u64().expect("index") as usize].clone(),
        "array" => {
            if let Some(length) = schema.get(2).and_then(Value::as_u64) {
                format!(
                    "readonly [{}]",
                    std::iter::repeat_n(typescript(&schema[1], parameters), length as usize)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!("readonly ({})[]", typescript(&schema[1], parameters))
            }
        }
        "map" => format!(
            "Readonly<Record<string, {}>>",
            typescript(&schema[1], parameters)
        ),
        "reference" => {
            let name = schema[1].as_str().expect("name");
            let args = schema[2].as_array().expect("arguments");
            if args.is_empty() {
                name.into()
            } else {
                format!(
                    "{name}<{}>",
                    args.iter()
                        .map(|arg| typescript(arg, parameters))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
        "union" => schema[1]
            .as_array()
            .expect("variants")
            .iter()
            .map(|arg| typescript(arg, parameters))
            .collect::<Vec<_>>()
            .join(" | "),
        "object" => format!(
            "{{ {} }}",
            schema[1]
                .as_object()
                .expect("properties")
                .iter()
                .map(|(name, value)| format!(
                    "readonly {}: {};",
                    json!(name),
                    typescript(value, parameters)
                ))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        _ => panic!("unknown shape"),
    }
}

fn generate(sources: &[&str]) -> String {
    let definitions = definitions(sources);
    let mut output =
        String::from("// Generated from sandsurf-protocol Rust/serde definitions. Do not edit.\n");
    for (name, value) in [
        ("SANDSURF_HEADER_BYTES", sandsurf_protocol::HEADER_BYTES),
        (
            "SANDSURF_AUTHENTICATION_BYTES",
            sandsurf_protocol::AUTHENTICATION_BYTES,
        ),
        (
            "SANDSURF_MAX_CONTROL_BYTES",
            sandsurf_protocol::MAX_CONTROL_BYTES,
        ),
        (
            "SANDSURF_MAX_STREAM_BYTES",
            sandsurf_protocol::MAX_STREAM_BYTES,
        ),
        (
            "SANDSURF_PROTOCOL_VERSION",
            usize::from(sandsurf_protocol::VERSION),
        ),
    ] {
        writeln!(output, "export const {name} = {value};").expect("string write");
    }
    writeln!(
        output,
        "export const SANDSURF_FRAME_MAGIC = {} as const;",
        json!(sandsurf_protocol::MAGIC)
    )
    .expect("string write");
    for (name, (params, schema)) in &definitions {
        let generic = if params.is_empty() {
            String::new()
        } else {
            format!("<{}>", params.join(", "))
        };
        writeln!(
            output,
            "export type {name}{generic} = {};",
            typescript(schema, params)
        )
        .expect("string write");
    }
    output.push_str("\nexport interface ProtocolTypes {\n");
    for (name, (params, _)) in &definitions {
        if params.is_empty() {
            writeln!(output, "  readonly {name}: {name};").expect("string write");
        }
    }
    output.push_str(
        "}\n\nexport const protocolShapes: Readonly<Record<string, readonly unknown[]>> = ",
    );
    output.push_str(
        &serde_json::to_string(
            &definitions
                .iter()
                .map(|(name, (_, schema))| (name, schema))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("schema JSON"),
    );
    output.push_str(";\n");
    output
}

fn main() {
    let output = generate(SOURCES);
    match std::env::args().nth(1).as_deref() {
        None => print!("{output}"),
        Some("--check") => {
            let destination = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../packages/sandsurf/src/protocol-generated.ts");
            assert!(
                std::fs::read_to_string(destination).expect("generated contract") == output,
                "generated protocol is stale; run npm run generate:protocol"
            );
        }
        _ => panic!("usage: sandsurf-protocol-typescript [--check]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_names_nullability_generics_and_tagged_newtypes_are_source_derived() {
        let source = r#"
            #[serde(rename_all = "camelCase", deny_unknown_fields)]
            pub struct Inner { pub some_value: Option<u16> }
            #[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
            pub enum State<T> { Ready { value: T }, Exited(Inner) }
        "#;
        let output = generate(&[source]);
        assert!(output.contains("readonly \"someValue\": null | number;"));
        assert!(output.contains("export type State<T>"));
        assert!(output.contains("readonly \"kind\": \"exited\"; readonly \"someValue\""));
        assert!(output.contains("[\"integer\",0,65535]"));
        assert!(output.contains("[\"parameter\",0]"));
    }

    #[test]
    #[should_panic(expected = "unsupported serde attribute")]
    fn changed_serde_representation_cannot_silently_weaken_the_generated_codec() {
        generate(&[r#"#[serde(untagged)] pub enum Changed { A }"#]);
    }

    #[test]
    fn every_current_protocol_definition_resolves() {
        let output = generate(SOURCES);
        assert!(output.contains("export type GuestCommand"));
        assert!(output.contains("export type RuntimeResponse"));
        assert!(output.contains("export type ReleaseRequest"));
    }
}
