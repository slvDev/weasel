use crate::config::initialize_config_file;

pub fn handle_init_command() {
    match initialize_config_file(None) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error during initialization: {}", e);
            std::process::exit(1);
        }
    }
}
