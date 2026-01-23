use super::tools::AiTool;
use serde_json::Value;
use std::fs;
use toml;

pub fn handle_remove(target: Option<String>) {
    println!("Removing Weasel MCP server...\n");

    let tools_to_configure = match &target {
        Some(target_id) => match AiTool::from_id(target_id) {
            Some(tool) => vec![tool],
            None => {
                eprintln!("Unknown target: {}", target_id);
                eprintln!("Available targets: claude, cursor, windsurf, codex, gemini");
                std::process::exit(1);
            }
        },
        None => AiTool::detect_installed(),
    };

    if tools_to_configure.is_empty() {
        println!("No AI tools with Weasel configuration found.");
        return;
    }

    let mut success_count = 0;

    for tool in &tools_to_configure {
        match remove_from_tool(tool) {
            Ok(removed) => {
                if removed {
                    println!("  [+] {} - removed", tool.name());
                    success_count += 1;
                } else {
                    println!("  [-] {} - not configured", tool.name());
                }
            }
            Err(e) => {
                eprintln!("  [x] {} - failed: {}", tool.name(), e);
            }
        }
    }

    if success_count > 0 {
        println!("\nDone! Restart your AI tools to apply changes.");
    } else {
        println!("\nNo Weasel configurations found to remove.");
    }
}

fn remove_from_tool(tool: &AiTool) -> Result<bool, String> {
    if tool.uses_toml() {
        return remove_from_toml_config(tool);
    }

    let config_path = match tool.config_path() {
        Some(path) if path.exists() => path,
        _ => return Ok(false),
    };

    let content =
        fs::read_to_string(&config_path).map_err(|e| format!("Failed to read config: {}", e))?;

    let mut config: Value =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))?;

    // Check if mcpServers.weasel exists
    let removed = if let Some(mcp_servers) = config
        .as_object_mut()
        .and_then(|obj| obj.get_mut("mcpServers"))
        .and_then(|v| v.as_object_mut())
    {
        mcp_servers.remove("weasel").is_some()
    } else {
        false
    };

    if removed {
        let output = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        fs::write(&config_path, output).map_err(|e| format!("Failed to write config: {}", e))?;
    }

    Ok(removed)
}

fn remove_from_toml_config(tool: &AiTool) -> Result<bool, String> {
    let config_path = match tool.config_path() {
        Some(path) if path.exists() => path,
        _ => return Ok(false),
    };

    let content =
        fs::read_to_string(&config_path).map_err(|e| format!("Failed to read config: {}", e))?;

    let mut config: toml::Table = content
        .parse()
        .map_err(|e| format!("Failed to parse TOML: {}", e))?;

    // Check if mcp_servers.weasel exists
    let removed = if let Some(mcp_servers) = config
        .get_mut("mcp_servers")
        .and_then(|v| v.as_table_mut())
    {
        mcp_servers.remove("weasel").is_some()
    } else {
        false
    };

    if removed {
        let output = toml::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize TOML: {}", e))?;

        fs::write(&config_path, output).map_err(|e| format!("Failed to write config: {}", e))?;
    }

    Ok(removed)
}
