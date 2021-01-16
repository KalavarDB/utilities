use crate::utilities::terminal::output::OutputManager;
use crate::management::{
    security::SecurityDatabase,
    versions::VersionManager,
};

#[test]
fn test_db_fetch() {
    let mut visual_manager: OutputManager = OutputManager::new(0);
    let mut test = SecurityDatabase::new();
    let update_result = test.update();
    if update_result.is_ok() {
        assert_eq!(1, 1)
    } else {
        visual_manager.debug_error(update_result.unwrap_err());
        assert_eq!(1, 2)
    }
}

#[test]
fn test_manifest_parser() {
    let mut crate_mgr = VersionManager::new();
    crate_mgr.fetch_dependencies("test-manifest.toml");
    for dependency in crate_mgr.dependencies {
        println!("{} - semver: {} - {}", dependency.name, dependency.version.is_semver, dependency.version);
        println!("{:#?}", dependency.version);
    }
}