
use crate::utilities::terminal::output::{OutputManager, DisplayLine};
use crate::management::{
    versions::VersionManager,
    security::SecurityDatabase,
};

pub fn parse_args(manifest: Option<&str>, recursion: usize, updates: bool) {
    let visual_manager: OutputManager = OutputManager::new(0, 112);
    let version_mgr = VersionManager::new();

    if updates {
        version_mgr.check_self_update(&visual_manager);
    }

    let mut advisory_db = SecurityDatabase::new();
    let update_result = advisory_db.update();
    if update_result.is_ok() {
        let fetch_result = if let Some(manpath) = manifest {
            version_mgr.fetch_dependencies(manpath, &visual_manager, &advisory_db, recursion)
        } else {
            version_mgr.fetch_dependencies("Cargo.toml", &visual_manager, &advisory_db, recursion)
        };
        if let Ok((good, bad, insecure, warn)) = fetch_result {
            visual_manager::render(DisplayLine::new_guide());
            visual_manager::render(DisplayLine::new_footer());
            visual_manager::render(DisplayLine::new_guide());
            visual_manager::render(DisplayLine::new_footer_content(good, bad, insecure, warn));
            visual_manager::render(DisplayLine::new_table_end());
        } else {}
    } else {
        visual_manager.error(update_result.unwrap_err())
    }
}