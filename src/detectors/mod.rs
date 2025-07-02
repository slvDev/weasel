use crate::core::visitor::ASTVisitor;
use crate::models::Severity;
use std::fmt;
use std::sync::Arc;

pub mod gas;
pub mod high;
pub mod nc;

pub trait Detector: Send + Sync + 'static {
    fn id(&self) -> &'static str;
    fn name(&self) -> &str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &str;
    fn example(&self) -> Option<String>;

    /// Register callbacks with the AST visitor.
    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor);
}

impl fmt::Display for dyn Detector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut msg = format!(
            "Name: {}\nSeverity: {}\nDescription: {}",
            self.name(),
            self.severity(),
            self.description()
        );

        if let Some(example) = self.example() {
            msg += &format!("\nExample: {}", example);
        }

        write!(f, "{}", msg)
    }
}
