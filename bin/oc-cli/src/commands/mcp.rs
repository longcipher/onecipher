use std::{
    io::{BufRead, Write},
    path::PathBuf,
};

use serde_json::{Value, json};

use crate::CliError;

const PROTOCOL_VERSION: &str = "2025-06-18";

pub(crate) fn run(manifest: Option<&PathBuf>, environment: Option<&str>) -> Result<(), CliError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_with_io(stdin.lock(), stdout.lock(), manifest.cloned(), environment.map(ToOwned::to_owned))
}

fn run_with_io<R: BufRead, W: Write>(
    reader: R,
    mut writer: W,
    manifest: Option<PathBuf>,
    environment: Option<String>,
) -> Result<(), CliError> {
    let mut server =
        McpServer { manifest, environment, lifecycle: SessionLifecycle::AwaitingInitialize };
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(error) => {
                write_json_line(
                    &mut writer,
                    &jsonrpc_error(Value::Null, -32700, format!("parse error: {error}")),
                )?;
                continue;
            }
        };
        if let Some(response) = server.handle_message(&message) {
            write_json_line(&mut writer, &response)?;
        }
    }
    Ok(())
}

struct McpServer {
    manifest: Option<PathBuf>,
    environment: Option<String>,
    lifecycle: SessionLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionLifecycle {
    AwaitingInitialize,
    AwaitingInitializedNotification,
    Ready,
}

impl McpServer {
    fn handle_message(&mut self, message: &Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message.get("method")?.as_str()?;
        match method {
            "initialize" => Some(self.handle_initialize(id.unwrap_or(Value::Null))),
            "notifications/initialized" => self.handle_initialized_notification(id),
            "ping" => Some(jsonrpc_result(id.unwrap_or(Value::Null), json!({}))),
            "tools/list" => {
                if let Some(response) = self.not_ready_response(id.clone()) {
                    Some(response)
                } else {
                    Some(jsonrpc_result(
                        id.unwrap_or(Value::Null),
                        json!({ "tools": Self::tools() }),
                    ))
                }
            }
            "tools/call" => {
                if let Some(response) = self.not_ready_response(id.clone()) {
                    Some(response)
                } else {
                    Some(self.handle_tool_call(
                        id.unwrap_or(Value::Null),
                        message.get("params").unwrap_or(&Value::Null),
                    ))
                }
            }
            _ => Some(jsonrpc_error(
                id.unwrap_or(Value::Null),
                -32601,
                format!("method not found: {method}"),
            )),
        }
    }

    fn handle_initialize(&mut self, id: Value) -> Value {
        if self.lifecycle != SessionLifecycle::AwaitingInitialize {
            return jsonrpc_error(id, -32600, "initialize may only be called once");
        }
        self.lifecycle = SessionLifecycle::AwaitingInitializedNotification;
        jsonrpc_result(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "onecipher",
                    "title": "OneCipher MCP Server",
                    "version": env!("OC_VERSION"),
                },
                "instructions": "OneCipher exposes project environment metadata and validation tools. Secret values are never returned over MCP."
            }),
        )
    }

    fn handle_initialized_notification(&mut self, id: Option<Value>) -> Option<Value> {
        match self.lifecycle {
            SessionLifecycle::AwaitingInitializedNotification => {
                self.lifecycle = SessionLifecycle::Ready;
                None
            }
            SessionLifecycle::AwaitingInitialize => {
                id.map(|value| jsonrpc_error(value, -32600, "initialize must be called first"))
            }
            SessionLifecycle::Ready => id.map(|value| {
                jsonrpc_error(value, -32600, "notifications/initialized already received")
            }),
        }
    }

    fn not_ready_response(&self, id: Option<Value>) -> Option<Value> {
        match self.lifecycle {
            SessionLifecycle::Ready => None,
            SessionLifecycle::AwaitingInitialize => Some(jsonrpc_error(
                id.unwrap_or(Value::Null),
                -32002,
                "server not initialized: call initialize first",
            )),
            SessionLifecycle::AwaitingInitializedNotification => Some(jsonrpc_error(
                id.unwrap_or(Value::Null),
                -32002,
                "server not initialized: wait for notifications/initialized",
            )),
        }
    }

    fn tools() -> Vec<Value> {
        vec![
            json!({
                "name": "onecipher_list_environments",
                "title": "List OneCipher environments",
                "description": "List environment names from the OneCipher project manifest without returning secret values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }),
            json!({
                "name": "onecipher_list_environment_variables",
                "title": "List environment variables",
                "description": "List variable names and secret references for a OneCipher environment without returning secret values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "environment": { "type": "string" }
                    }
                }
            }),
            json!({
                "name": "onecipher_validate_environment",
                "title": "Validate environment references",
                "description": "Validate that a OneCipher environment manifest resolves successfully. Secret values are not returned.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "environment": { "type": "string" }
                    }
                }
            }),
        ]
    }

    fn handle_tool_call(&self, id: Value, params: &Value) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return jsonrpc_error(id, -32602, "tools/call requires params.name");
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        let outcome = match name {
            "onecipher_list_environments" => self.tool_list_environments(),
            "onecipher_list_environment_variables" => self.tool_list_environment_variables(
                arguments.get("environment").and_then(Value::as_str),
            ),
            "onecipher_validate_environment" => {
                self.tool_validate_environment(arguments.get("environment").and_then(Value::as_str))
            }
            _ => {
                return jsonrpc_error(id, -32602, format!("unknown tool: {name}"));
            }
        };
        match outcome {
            Ok(structured) => jsonrpc_result(
                id,
                json!({
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&structured).unwrap_or_default() }],
                    "structuredContent": structured,
                    "isError": false
                }),
            ),
            Err(error) => jsonrpc_result(
                id,
                json!({
                    "content": [{ "type": "text", "text": error.to_string() }],
                    "isError": true
                }),
            ),
        }
    }

    fn tool_list_environments(&self) -> Result<Value, CliError> {
        let (path, manifest) = self.load_manifest()?;
        let environments =
            manifest.environments.keys().map(|name| json!({ "name": name })).collect::<Vec<_>>();
        Ok(json!({
            "manifestPath": path.display().to_string(),
            "defaultEnvironment": manifest.default_environment,
            "environments": environments,
        }))
    }

    fn tool_list_environment_variables(
        &self,
        requested_environment: Option<&str>,
    ) -> Result<Value, CliError> {
        let (path, manifest) = self.load_manifest()?;
        let selected = manifest
            .selected_environment_name(requested_environment.or(self.environment.as_deref()))?
            .to_string();
        let variables = manifest
            .bindings_for(Some(&selected))?
            .into_iter()
            .map(|(key, raw_reference)| {
                let reference = super::env_support::parse_secret_reference(&raw_reference)?;
                Ok(json!({
                    "key": key,
                    "reference": raw_reference,
                    "secretName": reference.name,
                    "field": reference.field.as_str(),
                }))
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        Ok(json!({
            "manifestPath": path.display().to_string(),
            "environment": selected,
            "variables": variables,
        }))
    }

    fn tool_validate_environment(
        &self,
        requested_environment: Option<&str>,
    ) -> Result<Value, CliError> {
        let (path, manifest) = self.load_manifest()?;
        let selected = manifest
            .selected_environment_name(requested_environment.or(self.environment.as_deref()))?
            .to_string();
        let store = super::open_secret_store()?;
        let identity = super::load_age_identity()?;
        let results = manifest
            .bindings_for(Some(&selected))?
            .into_iter()
            .map(|(key, raw_reference)| {
                let reference = super::env_support::parse_secret_reference(&raw_reference)?;
                Ok(serde_json::to_value(super::env_support::validate_reference_binding(
                    &store,
                    &identity,
                    &key,
                    &raw_reference,
                    &reference,
                ))?)
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        let ok =
            results.iter().all(|entry| entry.get("ok").and_then(Value::as_bool).unwrap_or(false));
        Ok(json!({
            "manifestPath": path.display().to_string(),
            "environment": selected,
            "ok": ok,
            "results": results,
        }))
    }

    fn load_manifest(
        &self,
    ) -> Result<(PathBuf, super::env_manifest::EnvironmentManifest), CliError> {
        let path = super::env_manifest::resolve_manifest_path(self.manifest.as_deref())?;
        let manifest = super::env_manifest::EnvironmentManifest::load(&path)?;
        Ok((path, manifest))
    }
}

fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn jsonrpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into(),
        }
    })
}

fn write_json_line<W: Write>(writer: &mut W, value: &Value) -> Result<(), CliError> {
    writer.write_all(serde_json::to_string(value)?.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_env(k: &str, v: &str) {
        unsafe { std::env::set_var(k, v) };
    }

    fn remove_env(k: &str) {
        unsafe { std::env::remove_var(k) };
    }

    #[test]
    fn mcp_server_handles_initialize_and_tools() {
        let _home = crate::test_util::HomeGuard::new();
        super::super::age_cmd::init().unwrap();
        set_env("ONECIPHER_SECRET", "mcp-secret");
        super::super::secret::add("api/openai", oc_core::ItemType::Password, &[], false).unwrap();
        remove_env("ONECIPHER_SECRET");

        let project = tempfile::tempdir().unwrap();
        let cfg_dir = project.path().join(".onecipher");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let manifest = cfg_dir.join("environments.toml");
        std::fs::write(
            &manifest,
            r#"
version = 1
default_environment = "default"

[environments.default]
OPENAI_API_KEY = "oc://api/openai"
"#,
        )
        .unwrap();

        let input = [
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1.0.0" }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "onecipher_validate_environment",
                    "arguments": { "environment": "default" }
                }
            }),
        ]
        .into_iter()
        .map(|value| serde_json::to_string(&value).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
        let mut output = Vec::new();

        run_with_io(
            std::io::Cursor::new(input),
            &mut output,
            Some(manifest),
            Some("default".to_string()),
        )
        .unwrap();

        let lines = String::from_utf8(output).unwrap();
        assert!(lines.contains("\"protocolVersion\":\"2025-06-18\""));
        assert!(lines.contains("onecipher_list_environments"));
        assert!(lines.contains("\"ok\":true"));
    }

    #[test]
    fn mcp_server_rejects_tools_before_initialize() {
        let input = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }))
        .unwrap();
        let mut output = Vec::new();

        run_with_io(std::io::Cursor::new(input), &mut output, None, None).unwrap();

        let lines = String::from_utf8(output).unwrap();
        assert!(lines.contains("\"code\":-32002"), "output: {lines}");
    }

    #[test]
    fn mcp_server_rejects_tools_before_initialized_notification() {
        let input = [
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1.0.0" }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }),
        ]
        .into_iter()
        .map(|value| serde_json::to_string(&value).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
        let mut output = Vec::new();

        run_with_io(std::io::Cursor::new(input), &mut output, None, None).unwrap();

        let lines = String::from_utf8(output).unwrap();
        assert!(lines.contains("\"protocolVersion\":\"2025-06-18\""), "output: {lines}");
        assert!(lines.contains("\"code\":-32002"), "output: {lines}");
    }
}
