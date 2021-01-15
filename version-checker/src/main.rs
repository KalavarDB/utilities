use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

use reqwest::blocking::ClientBuilder;
use regex::Regex;
use crates_io_api::{CrateResponse, Error};
use std::process::exit;
use std::collections::HashMap;
use crate::utilities::terminal::output::{OutputManager, DisplayLine};
use crate::management::crates_io::{CratesIOManager, Dependency, Version};


pub mod management;
pub mod utilities;

#[cfg(test)]
pub mod tests;

pub const VERSION: &str = "0.1.1";

fn main() {
    let mut visual_manager: OutputManager = OutputManager::new(0, 112);
    let mut crate_mgr = CratesIOManager::new();
    crate_mgr.check_self_update(&visual_manager);
    let mut advisory_db = management::security::SecurityDatabase::new();
    let update_result = advisory_db.update();
    if update_result.is_ok() {
        visual_manager.render(DisplayLine::new_title("Version Checker Utility  Version 0.1.1"));
        visual_manager.render(DisplayLine::new_header());
        visual_manager.render(DisplayLine::new_guide());
        let fetch_result = crate_mgr.fetch_dependencies("test-manifest.toml", &visual_manager, &advisory_db);
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
