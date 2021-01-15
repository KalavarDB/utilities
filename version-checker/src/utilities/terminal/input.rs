use crate::utilities::terminal::output::{OutputManager, DisplayLine};
use crate::management::{
    crates_io::CratesIOManager,
    security::SecurityDatabase,
};

pub fn parse_args(manifest: Option<&str>, recursion: usize, updates: bool) {
    let visual_manager: OutputManager = OutputManager::new(0, 112);
    let crate_mgr = CratesIOManager::new();

    if updates {
        crate_mgr.check_self_update(&visual_manager);
    }

    let mut advisory_db = SecurityDatabase::new();
    let update_result = advisory_db.update();
    if update_result.is_ok() {
        visual_manager.render(DisplayLine::new_title("Version Checker Utility  Version 0.1.1"));
        visual_manager.render(DisplayLine::new_header());
        visual_manager.render(DisplayLine::new_guide());
        let fetch_result = if let Some(manpath) = manifest {
            crate_mgr.fetch_dependencies(manpath, &visual_manager, &advisory_db, recursion)
        } else {
            crate_mgr.fetch_dependencies("Cargo.toml", &visual_manager, &advisory_db, recursion)
        };
        if let Ok((good, bad, insecure, warn)) = fetch_result {
            visual_manager.render(DisplayLine::new_guide());
            visual_manager.render(DisplayLine::new_footer());
            visual_manager.render(DisplayLine::new_guide());
            visual_manager.render(DisplayLine::new_footer_content(good, bad, insecure, warn));
            visual_manager.render(DisplayLine::new_table_end());
        } else {}
    } else {
        visual_manager.error(update_result.unwrap_err())
    }
}