use super::executors::{execute_analyze, execute_detectors, execute_finding_details, JsonRpcError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const SERVER_NAME: &str = "weasel";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

pub fn handle_serve() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        // Try to parse as batch (array) first, then as single request
        let parsed: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let error_response = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                        data: None,
                    }),
                };
                write_response(&mut stdout_lock, &error_response);
                continue;
            }
        };

        if parsed.is_array() {
            // Batch request - process each and return array of responses
            let requests: Vec<JsonRpcRequest> = match serde_json::from_value(parsed) {
                Ok(reqs) => reqs,
                Err(e) => {
                    let error_response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: None,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32700,
                            message: format!("Batch parse error: {}", e),
                            data: None,
                        }),
                    };
                    write_response(&mut stdout_lock, &error_response);
                    continue;
                }
            };

            let responses: Vec<JsonRpcResponse> = requests
                .iter()
                .filter_map(|req| process_single_request(req))
                .collect();

            // Only write batch response if there are responses (not all notifications)
            if !responses.is_empty() {
                write_batch_response(&mut stdout_lock, &responses);
            }
        } else {
            // Single request
            let request: JsonRpcRequest = match serde_json::from_value(parsed) {
                Ok(req) => req,
                Err(e) => {
                    let error_response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: None,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32700,
                            message: format!("Parse error: {}", e),
                            data: None,
                        }),
                    };
                    write_response(&mut stdout_lock, &error_response);
                    continue;
                }
            };

            if let Some(response) = process_single_request(&request) {
                write_response(&mut stdout_lock, &response);
            }
        }
    }
}

fn process_single_request(request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    // Validate JSON-RPC version
    if request.jsonrpc != "2.0" {
        return Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: None,
            error: Some(JsonRpcError {
                code: -32600,
                message: format!(
                    "Invalid JSON-RPC version: expected 2.0, got {}",
                    request.jsonrpc
                ),
                data: None,
            }),
        });
    }

    handle_request(request)
}

fn write_response<W: Write>(writer: &mut W, response: &JsonRpcResponse) {
    if let Ok(json) = serde_json::to_string(response) {
        let _ = writeln!(writer, "{}", json);
        let _ = writer.flush();
    }
}

fn write_batch_response<W: Write>(writer: &mut W, responses: &[JsonRpcResponse]) {
    if let Ok(json) = serde_json::to_string(responses) {
        let _ = writeln!(writer, "{}", json);
        let _ = writer.flush();
    }
}

fn handle_request(request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    let result = match request.method.as_str() {
        "initialize" => handle_initialize(),
        "notifications/initialized" => return None, // Notification - no response
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(&request.params),
        "resources/list" => Ok(json!({"resources": []})),
        "prompts/list" => Ok(json!({"prompts": []})),
        "ping" => Ok(json!({})),
        _ => Err(JsonRpcError {
            code: -32601,
            message: format!("Method not found: {}", request.method),
            data: None,
        }),
    };

    Some(match result {
        Ok(value) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: Some(value),
            error: None,
        },
        Err(error) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: None,
            error: Some(error),
        },
    })
}

fn handle_initialize() -> Result<Value, JsonRpcError> {
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {},
            "resources": {},
            "prompts": {}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION
        }
    }))
}

fn handle_tools_list() -> Result<Value, JsonRpcError> {
    Ok(json!({
        "tools": [
            {
                "name": "weasel_analyze",
                "description": "Run Weasel static analysis on Solidity smart contracts. Returns compact summary of all findings. Use weasel_finding_details to get full details for specific issues.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the Solidity file or directory to analyze. Defaults to current directory."
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["High", "Medium", "Low", "Gas", "NC"],
                            "description": "Minimum severity level to report. NC includes all issues."
                        },
                        "exclude": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Paths to exclude from analysis (e.g., ['test', 'mocks', 'interfaces'])"
                        },
                        "exclude_detectors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Detector IDs to exclude from analysis (e.g., ['floating-pragma', 'unused-import'])"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "weasel_finding_details",
                "description": "Get detailed information about a specific finding type, including description, code snippets, and fix suggestions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "detector": {
                            "type": "string",
                            "description": "The detector ID to get details for (e.g., 'delegatecall-in-loop')"
                        },
                        "path": {
                            "type": "string",
                            "description": "Path that was analyzed (to retrieve cached results)"
                        }
                    },
                    "required": ["detector"]
                }
            },
            {
                "name": "weasel_detectors",
                "description": "List all available Weasel detectors with their descriptions and severity levels.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["High", "Medium", "Low", "Gas", "NC"],
                            "description": "Filter detectors by severity level."
                        }
                    },
                    "required": []
                }
            }
        ]
    }))
}

fn handle_tools_call(params: &Value) -> Result<Value, JsonRpcError> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "Missing tool name".to_string(),
            data: None,
        })?;

    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "weasel_analyze" => execute_analyze(&arguments),
        "weasel_finding_details" => execute_finding_details(&arguments),
        "weasel_detectors" => execute_detectors(&arguments),
        _ => Err(JsonRpcError {
            code: -32602,
            message: format!("Unknown tool: {}", name),
            data: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, id: Option<i32>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: id.map(|i| Value::Number(i.into())),
            method: method.to_string(),
            params: json!({}),
        }
    }

    #[test]
    fn test_handle_initialize() {
        let result = handle_initialize().unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["capabilities"]["resources"].is_object());
        assert!(result["capabilities"]["prompts"].is_object());
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn test_handle_tools_list() {
        let result = handle_tools_list().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3);

        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"weasel_analyze"));
        assert!(names.contains(&"weasel_finding_details"));
        assert!(names.contains(&"weasel_detectors"));
    }

    #[test]
    fn test_handle_request_unknown_method() {
        let request = make_request("unknown/method", Some(1));
        let response = handle_request(&request).unwrap();

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32601);
        assert!(error.message.contains("Method not found"));
    }

    #[test]
    fn test_notification_returns_none() {
        let request = make_request("notifications/initialized", None);
        let response = handle_request(&request);
        assert!(response.is_none());
    }

    #[test]
    fn test_batch_request_processing() {
        let requests = vec![
            make_request("initialize", Some(1)),
            make_request("tools/list", Some(2)),
        ];

        let responses: Vec<JsonRpcResponse> = requests
            .iter()
            .filter_map(|req| process_single_request(req))
            .collect();

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].id, Some(Value::Number(1.into())));
        assert_eq!(responses[1].id, Some(Value::Number(2.into())));
        assert!(responses[0].result.is_some());
        assert!(responses[1].result.is_some());
    }

    #[test]
    fn test_batch_with_notification_filters_response() {
        let requests = vec![
            make_request("initialize", Some(1)),
            make_request("notifications/initialized", None), // notification - no response
            make_request("tools/list", Some(2)),
        ];

        let responses: Vec<JsonRpcResponse> = requests
            .iter()
            .filter_map(|req| process_single_request(req))
            .collect();

        // Should only have 2 responses (notification filtered out)
        assert_eq!(responses.len(), 2);
    }
}
