use crate::config::Config;
use crate::core::engine::AnalysisEngine;

pub fn handle_detectors_command(severity: Option<String>, details: Option<String>) {
    let config = Config::default();
    let mut engine = AnalysisEngine::new(&config);
    engine.register_built_in_detectors();
    let registry = engine.registry();

    if let Some(detector_id) = details {
        if let Some(detector) = registry.get(&detector_id) {
            println!("{}", detector);
        } else {
            eprintln!("Error: Detector with ID '{}' not found.", detector_id);
        }
        return;
    }

    let detectors = if let Some(sev_str) = &severity {
        match sev_str.parse() {
            Ok(sev) => {
                println!("\nAvailable detectors filtered by severity: {}", sev);
                registry.get_by_severity(&sev)
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                eprintln!("Acceptable values: high, medium, low, gas, nc");
                std::process::exit(1);
            }
        }
    } else {
        println!("\nAvailable detectors (Total: {}):", registry.count());
        registry.get_all()
    };

    if detectors.is_empty() {
        println!("No detectors found");
    } else {
        for detector in detectors {
            println!(
                "({}) - {}: {}",
                detector.severity(),
                detector.id(),
                detector.name(),
            );
        }
    }
}
