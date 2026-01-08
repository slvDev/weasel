pub mod add;
mod executors;
pub mod remove;
pub mod serve;
pub mod tools;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum McpCommands {
    /// Add Weasel MCP server to AI tools (Claude Code, Cursor, Windsurf)
    Add {
        /// Target specific tool (claude, cursor, windsurf)
        #[arg(short, long)]
        target: Option<String>,
    },
    /// Remove Weasel MCP server from AI tools
    Remove {
        /// Target specific tool (claude, cursor, windsurf)
        #[arg(short, long)]
        target: Option<String>,
    },
    /// Run MCP server (used internally by AI tools)
    Serve,
}

pub fn handle_mcp_command(command: McpCommands) {
    match command {
        McpCommands::Add { target } => add::handle_add(target),
        McpCommands::Remove { target } => remove::handle_remove(target),
        McpCommands::Serve => serve::handle_serve(),
    }
}
