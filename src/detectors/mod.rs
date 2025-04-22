use crate::core::visitor::ASTVisitor;
use crate::models::finding::Location;
use crate::models::Severity;
use std::sync::{Arc, Mutex};

pub mod nc;

pub trait Detector: Send + Sync + 'static {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &str;
    fn gas_savings(&self) -> Option<usize>;
    fn example(&self) -> Option<String>;

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>>;

    fn locations(&self) -> Vec<Location> {
        if let Ok(locations) = self.get_locations_arc().lock() {
            locations.clone()
        } else {
            eprintln!(
                "Error: Mutex poisoned when getting locations for detector {}",
                self.id()
            );
            Vec::new()
        }
    }

    fn add_location(&self, location: Location) {
        if let Ok(mut locations) = self.get_locations_arc().lock() {
            locations.push(location);
        } else {
            eprintln!(
                "Error: Mutex poisoned when adding location for detector {}",
                self.id()
            );
        }
    }

    /// Register callbacks with the AST visitor.
    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor);
}
