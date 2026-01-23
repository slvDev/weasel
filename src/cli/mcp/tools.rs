use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AiTool {
    ClaudeCode,
    Cursor,
    Windsurf,
    Codex,
    Gemini,
}

impl AiTool {
    pub fn name(&self) -> &'static str {
        match self {
            AiTool::ClaudeCode => "Claude Code",
            AiTool::Cursor => "Cursor",
            AiTool::Windsurf => "Windsurf",
            AiTool::Codex => "OpenAI Codex",
            AiTool::Gemini => "Gemini CLI",
        }
    }

    pub fn config_path(&self) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        Some(match self {
            AiTool::ClaudeCode => home.join(".claude.json"),
            AiTool::Cursor => home.join(".cursor").join("mcp.json"),
            AiTool::Windsurf => home
                .join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            AiTool::Codex => home.join(".codex").join("config.toml"),
            AiTool::Gemini => home.join(".gemini").join("settings.json"),
        })
    }

    pub fn is_installed(&self) -> bool {
        // Check if config file or parent directory exists
        if let Some(config_path) = self.config_path() {
            if config_path.exists() {
                return true;
            }
            // Check parent directory for tools that might not have config yet
            if let Some(parent) = config_path.parent() {
                if parent.exists() && parent != dirs::home_dir().unwrap_or_default() {
                    return true;
                }
            }
        }

        // Check if binary exists in PATH
        match self {
            AiTool::ClaudeCode => command_exists("claude"),
            AiTool::Cursor => command_exists("cursor"),
            AiTool::Windsurf => command_exists("windsurf"),
            AiTool::Codex => command_exists("codex"),
            AiTool::Gemini => command_exists("gemini"),
        }
    }

    pub fn all() -> &'static [AiTool] {
        &[AiTool::ClaudeCode, AiTool::Cursor, AiTool::Windsurf, AiTool::Codex, AiTool::Gemini]
    }

    pub fn from_id(id: &str) -> Option<AiTool> {
        match id.to_lowercase().as_str() {
            "claude" | "claude-code" | "claudecode" => Some(AiTool::ClaudeCode),
            "cursor" => Some(AiTool::Cursor),
            "windsurf" => Some(AiTool::Windsurf),
            "codex" | "openai" | "openai-codex" => Some(AiTool::Codex),
            "gemini" | "gemini-cli" => Some(AiTool::Gemini),
            _ => None,
        }
    }

    pub fn detect_installed() -> Vec<AiTool> {
        AiTool::all()
            .iter()
            .filter(|tool| tool.is_installed())
            .copied()
            .collect()
    }

    pub fn uses_toml(&self) -> bool {
        matches!(self, AiTool::Codex)
    }
}

fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
