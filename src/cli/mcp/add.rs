use super::tools::AiTool;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;
use toml;

pub fn handle_add(target: Option<String>) {
    println!("Detecting AI tools...\n");

    let tools_to_configure = match &target {
        Some(target_id) => {
            match AiTool::from_id(target_id) {
                Some(tool) => {
                    if tool.is_installed() {
                        vec![tool]
                    } else {
                        eprintln!("  [x] {} - not installed", tool.name());
                        std::process::exit(1);
                    }
                }
                None => {
                    eprintln!("Unknown target: {}", target_id);
                    eprintln!("Available targets: claude, cursor, windsurf, codex, gemini");
                    std::process::exit(1);
                }
            }
        }
        None => {
            let installed = AiTool::detect_installed();
            let all_tools = AiTool::all();

            for tool in all_tools {
                if installed.contains(tool) {
                    if let Some(path) = tool.config_path() {
                        println!("  [+] {} ({})", tool.name(), path.display());
                    } else {
                        println!("  [+] {}", tool.name());
                    }
                } else {
                    println!("  [x] {} - not installed", tool.name());
                }
            }

            if installed.is_empty() {
                eprintln!("\nNo supported AI tools detected.");
                eprintln!("Supported tools: Claude Code, Cursor, Windsurf, OpenAI Codex, Gemini CLI");
                std::process::exit(1);
            }

            installed
        }
    };

    println!("\nAdding Weasel MCP server...\n");

    let weasel_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Failed to get weasel executable path: {}", e);
            std::process::exit(1);
        }
    };

    let mut success_count = 0;

    for tool in &tools_to_configure {
        match add_to_tool(tool, &weasel_path) {
            Ok(()) => {
                println!("  [+] {} - added", tool.name());
                success_count += 1;
            }
            Err(e) => {
                eprintln!("  [x] {} - failed: {}", tool.name(), e);
            }
        }
    }

    if success_count > 0 {
        println!("\nDone! Restart your AI tools to use Weasel.");
        println!("\nAvailable commands in AI chat:");
        println!("  - \"analyze this contract with weasel\"");
        println!("  - \"run weasel on ./src\"");
    } else {
        eprintln!("\nFailed to add Weasel to any AI tool.");
        std::process::exit(1);
    }
}

fn add_to_tool(tool: &AiTool, weasel_path: &Path) -> Result<(), String> {
    if tool.uses_toml() {
        return add_to_toml_config(tool, weasel_path);
    }

    let config_path = tool
        .config_path()
        .ok_or_else(|| "Could not determine config path".to_string())?;

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }
    }

    // Read existing config or create empty one
    let mut config: Value = if config_path.exists() {
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))?
    } else {
        json!({})
    };

    // Ensure config is an object
    let config_obj = config
        .as_object_mut()
        .ok_or_else(|| "Config is not a JSON object".to_string())?;

    // Ensure mcpServers key exists
    if !config_obj.contains_key("mcpServers") {
        config_obj.insert("mcpServers".to_string(), json!({}));
    }

    // Get mcpServers object
    let mcp_servers = config_obj
        .get_mut("mcpServers")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| "mcpServers is not an object".to_string())?;

    // Create weasel server entry
    let weasel_entry = create_mcp_entry(weasel_path);

    // Add or update weasel entry
    mcp_servers.insert("weasel".to_string(), weasel_entry);

    // Write back to file
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    fs::write(&config_path, output).map_err(|e| format!("Failed to write config: {}", e))?;

    Ok(())
}

fn create_mcp_entry(weasel_path: &Path) -> Value {
    let mut entry = Map::new();
    entry.insert("type".to_string(), json!("stdio"));
    entry.insert(
        "command".to_string(),
        json!(weasel_path.to_string_lossy().to_string()),
    );
    entry.insert("args".to_string(), json!(["mcp", "serve"]));
    Value::Object(entry)
}

fn add_to_toml_config(tool: &AiTool, weasel_path: &Path) -> Result<(), String> {
    let config_path = tool
        .config_path()
        .ok_or_else(|| "Could not determine config path".to_string())?;

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }
    }

    // Read existing config or create empty
    let mut config: toml::Table = if config_path.exists() {
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        content
            .parse()
            .map_err(|e| format!("Failed to parse TOML: {}", e))?
    } else {
        toml::Table::new()
    };

    // Get or create mcp_servers table
    if !config.contains_key("mcp_servers") {
        config.insert(
            "mcp_servers".to_string(),
            toml::Value::Table(toml::Table::new()),
        );
    }

    let mcp_servers = config
        .get_mut("mcp_servers")
        .and_then(|v| v.as_table_mut())
        .ok_or_else(|| "mcp_servers is not a table".to_string())?;

    // Create weasel entry
    let mut weasel_entry = toml::Table::new();
    weasel_entry.insert(
        "command".to_string(),
        toml::Value::String(weasel_path.to_string_lossy().to_string()),
    );
    weasel_entry.insert(
        "args".to_string(),
        toml::Value::Array(vec![
            toml::Value::String("mcp".to_string()),
            toml::Value::String("serve".to_string()),
        ]),
    );

    mcp_servers.insert("weasel".to_string(), toml::Value::Table(weasel_entry));

    // Write back
    let output = toml::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize TOML: {}", e))?;
    fs::write(&config_path, output).map_err(|e| format!("Failed to write config: {}", e))?;

    Ok(())
}
