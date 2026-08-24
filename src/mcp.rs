use std::io::{BufRead as _, Write};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::agent::{AgentClient, ApprovalControl, CapabilityCall, PlanRequest};

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

pub fn serve(profile: &str) -> Result<()> {
    // Load and validate the protected signing key before advertising any tool.
    // The key stays in this process and is never included in an MCP response.
    let client = AgentClient::load(profile)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.context("read MCP stdio request")?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                write_response(
                    &mut output,
                    &rpc_error(Value::Null, -32700, &format!("invalid JSON: {error}")),
                )?;
                continue;
            }
        };
        if let Some(response) = handle(&client, &request) {
            write_response(&mut output, &response)?;
        }
    }
    Ok(())
}

fn handle(client: &AgentClient, request: &Value) -> Option<Value> {
    // MCP notifications never receive a response.
    let id = request.get("id").cloned()?;
    let method = request.get("method").and_then(Value::as_str);
    let response = match method {
        Some("initialize") => Ok(json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {
                "name": "thelve",
                "title": "Thelve governed administration",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Use read tools freely. Propose every mutation as an immutable plan, wait for a human decision, then apply by approval id. Never place secret values in plan input."
        })),
        Some("ping") => Ok(json!({})),
        Some("tools/list") => Ok(json!({"tools": tool_definitions()})),
        Some("tools/call") => tool_call(
            client,
            request
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            request
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({})),
        )
        .map(tool_success)
        .or_else(|error| Ok::<Value, anyhow::Error>(tool_failure(&error))),
        Some(method) => Err(anyhow!("unsupported MCP method {method:?}")),
        None => Err(anyhow!("MCP request is missing method")),
    };
    Some(match response {
        Ok(result) => rpc_result(id, result),
        Err(error) => rpc_error(id, -32601, &error.to_string()),
    })
}

fn tool_call(client: &AgentClient, name: &str, arguments: Value) -> Result<Value> {
    let object = arguments
        .as_object()
        .ok_or_else(|| anyhow!("tool arguments must be an object"))?;
    match name {
        "thelve_capabilities" => client.catalog(),
        "thelve_read" => {
            let capability = required_string(object, "capability")?;
            let call = CapabilityCall {
                capability,
                resource_type: optional_string(object, "resource_type")
                    .unwrap_or_else(|| "unspecified".into()),
                resource_id: optional_string(object, "resource_id"),
                input: optional_object(object, "input")?,
                approval_id: None,
                idempotency_key: Uuid::new_v4().to_string(),
            };
            let descriptor = client.descriptor(&call.capability)?;
            if descriptor.get("risk").and_then(Value::as_str) != Some("read") {
                bail!(
                    "capability {:?} is not a read; use thelve_plan",
                    call.capability
                );
            }
            client.invoke(call)
        }
        "thelve_plan" => {
            let control = match optional_string(object, "control").as_deref() {
                None | Some("confirmation") => ApprovalControl::Confirmation,
                Some("four_eyes") => ApprovalControl::FourEyes,
                Some(value) => bail!("unsupported control {value:?}"),
            };
            client.create_plan(PlanRequest {
                capability: required_string(object, "capability")?,
                resource_type: optional_string(object, "resource_type")
                    .unwrap_or_else(|| "unspecified".into()),
                resource_id: optional_string(object, "resource_id"),
                input: optional_object(object, "input")?,
                reason: required_string(object, "reason")?,
                control,
                expires_in_seconds: object
                    .get("expires_in_seconds")
                    .and_then(Value::as_u64)
                    .map_or(Ok(600), |value| {
                        u32::try_from(value).context("expires_in_seconds is too large")
                    })?,
                idempotency_key: optional_string(object, "idempotency_key"),
            })
        }
        "thelve_plan_read" => client.read_plan(required_uuid(object, "approval_id")?),
        "thelve_plan_list" => client.list_plans(
            optional_string(object, "status").as_deref(),
            object
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(Ok(50), |value| {
                    u16::try_from(value).context("limit is too large")
                })?,
        ),
        "thelve_plan_apply" => client.apply_plan(required_uuid(object, "approval_id")?),
        _ => bail!("unknown Thelve MCP tool {name:?}"),
    }
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "thelve_capabilities",
            "title": "Discover Thelve capabilities",
            "description": "Read the deployment's live signed-agent capability catalog, including risk, approval policy, AI availability, and content-addressed contracts.",
            "inputSchema": {"type": "object", "additionalProperties": false}
        }),
        json!({
            "name": "thelve_read",
            "title": "Read Thelve state",
            "description": "Invoke one catalog capability only when the live catalog marks it read-only. Mutations are refused and must use the plan flow.",
            "inputSchema": capability_input_schema(false)
        }),
        json!({
            "name": "thelve_plan",
            "title": "Propose an immutable Thelve change",
            "description": "Create a tenant-RLS approval record binding the exact capability, resource, complete input, digest, and one-operation idempotency key. Does not execute the change.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["capability", "input", "reason"],
                "properties": {
                    "capability": {"type": "string"},
                    "resource_type": {"type": "string", "default": "unspecified"},
                    "resource_id": {"type": "string"},
                    "input": {"type": "object"},
                    "reason": {"type": "string", "minLength": 1},
                    "control": {"type": "string", "enum": ["confirmation", "four_eyes"], "default": "confirmation"},
                    "expires_in_seconds": {"type": "integer", "minimum": 60, "maximum": 86400, "default": 600},
                    "idempotency_key": {"type": "string"}
                }
            }
        }),
        json!({
            "name": "thelve_plan_read",
            "title": "Read a Thelve plan",
            "description": "Read one immutable plan and human-decision state without executing it.",
            "inputSchema": approval_id_schema()
        }),
        json!({
            "name": "thelve_plan_list",
            "title": "List Thelve plans",
            "description": "List pending or decided immutable plans visible under the bounded delegation.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "status": {"type": "string", "enum": ["pending", "approved", "rejected", "expired", "cancelled"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50}
                }
            }
        }),
        json!({
            "name": "thelve_plan_apply",
            "title": "Apply an approved Thelve plan",
            "description": "Re-read an approved plan, verify its frozen input digest and scope, and invoke exactly those fields with the approval inside the signed AAuth envelope.",
            "inputSchema": approval_id_schema()
        }),
    ]
}

fn capability_input_schema(require_reason: bool) -> Value {
    let required = if require_reason {
        json!(["capability", "input", "reason"])
    } else {
        json!(["capability", "input"])
    };
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": {
            "capability": {"type": "string"},
            "resource_type": {"type": "string", "default": "unspecified"},
            "resource_id": {"type": "string"},
            "input": {"type": "object"}
        }
    })
}

fn approval_id_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["approval_id"],
        "properties": {"approval_id": {"type": "string", "format": "uuid"}}
    })
}

fn required_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<String> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{key} is required"))?;
    if value.trim().is_empty() {
        bail!("{key} cannot be blank");
    }
    Ok(value.to_owned())
}

fn optional_string(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn optional_object(object: &serde_json::Map<String, Value>, key: &str) -> Result<Value> {
    let value = object.get(key).cloned().unwrap_or_else(|| json!({}));
    if !value.is_object() {
        bail!("{key} must be an object");
    }
    Ok(value)
}

fn required_uuid(object: &serde_json::Map<String, Value>, key: &str) -> Result<Uuid> {
    Uuid::parse_str(&required_string(object, key)?).with_context(|| format!("parse {key}"))
}

fn tool_success(value: Value) -> Value {
    json!({
        "content": [{"type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())}],
        "structuredContent": value,
        "isError": false
    })
}

fn tool_failure(error: &anyhow::Error) -> Value {
    json!({
        "content": [{"type": "text", "text": format!("Thelve request refused: {error:#}")}],
        "isError": true
    })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

fn write_response(output: &mut impl Write, response: &Value) -> Result<()> {
    serde_json::to_writer(&mut *output, response).context("serialize MCP response")?;
    output.write_all(b"\n").context("write MCP response")?;
    output.flush().context("flush MCP response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_surface_has_no_arbitrary_http_or_unplanned_mutation() {
        let definitions = tool_definitions();
        let names: Vec<&str> = definitions
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"thelve_read"));
        assert!(names.contains(&"thelve_plan"));
        assert!(names.contains(&"thelve_plan_apply"));
        assert!(!names.iter().any(|name| name.contains("http")));
        assert!(!names.iter().any(|name| name.contains("invoke")));
    }
}
