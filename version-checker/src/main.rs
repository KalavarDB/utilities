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

fn main() {
    let mut visual_manager: OutputManager = OutputManager::new(0, 112);
    let mut test = management::security::SecurityDatabase::new();
    let update_result = test.update();
    if update_result.is_ok() {
        let mut crate_mgr = CratesIOManager::new();
        visual_manager.render(DisplayLine::new_title("Version Checker Utility  Version 0.1.1"));
        visual_manager.render(DisplayLine::new_header());
        visual_manager.render(DisplayLine::new_guide());
        let fetch_result = crate_mgr.fetch_dependencies("Cargo.toml", &visual_manager);
        if let Ok((good, bad, insecure, warn)) = fetch_result {
            visual_manager.render(DisplayLine::new_guide());
            visual_manager.render(DisplayLine::new_footer());
            visual_manager.render(DisplayLine::new_guide());
            visual_manager.render(DisplayLine::new_footer_content(insecure, good, bad, warn));
            visual_manager.render(DisplayLine::new_table_end());
        } else {

        }
    } else {
        visual_manager.error(update_result.unwrap_err())
    }

    /*
    if let Ok(mut file) = handle {

        println!("======================> Crate Version Checker 0.1 <======================");
        println!("Advisories  Crate                                        Version         ");
        println!("=========================================================================");
        let mut found_deps = false;
        for line in content.split(LINE_ENDING) {
            if !line.is_empty() {
                if line == "[dependencies]" {
                    found_deps = true;
                } else if found_deps {
                    if line.contains('{') {
                        let components: Vec<&str> = line.split(" = ").collect();
                        let mut container = components[0].to_string();

                        let pattern = Regex::new(r#"[\d.]+"#).unwrap();

                        let vcore = pattern.captures(line).unwrap().iter().last().unwrap().unwrap().as_str();
                        let mut pieces = vcore.split('.').collect::<Vec<&str>>();

                        while pieces.len() < 3 {
                            pieces.push("0");
                        }

                        let vfull: String = pieces.join(".");

                        let version = match Version::parse(vfull.as_str()) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("Failed to parse {}: {}", line, e);
                                exit(1);
                            }
                        };

                        let crate_res: Result<CrateResponse, Error> = client.get_crate(container.as_str());
                        if let Ok(response) = crate_res {
                            let mut rcore = "0.0.0".to_string();
                            for ver in response.versions {
                                let mut vnum = ver.num;

                                let mut rpieces = vnum.split('.').collect::<Vec<&str>>();

                                if rpieces.len() < 3 {
                                    rpieces.push("0");
                                }
                                vnum = rpieces.join(".");
                                let parsed = Version::parse(vnum.as_str()).unwrap();
                                let core = Version::parse(rcore.as_str()).unwrap();

                                if parsed > core {
                                    rcore = vnum;
                                }
                            }
                            let mut rpieces = rcore.split('.').collect::<Vec<&str>>();

                            if rpieces.len() < 3 {
                                rpieces.push("0");
                            }
                            let rfull: String = rpieces.join(".");
                            let remote = Version::parse(rfull.as_str()).unwrap();

                            let base_crate = container.clone();

                            while container.len() < 44 {
                                container = format!("{} ", container);
                            }

                            let mut color = "\x1b[32m";
                            if remote > version {
                                color = "\x1b[31m";
                                if advisories.contains_key(base_crate.as_str()) {
                                    let adv_tot = advisories.get(base_crate.as_str()).unwrap().len();
                                    sav += adv_tot;
                                    let mut adv_count = format!("\x1b[41m{}\x1b[0m", adv_tot.to_string());
                                    while adv_count.len() < 19 {
                                        adv_count = format!(" {}", adv_count);
                                    }
                                    println!("{}  {} {}{}\x1b[0m -> \x1b[32m{}\x1b[0m", adv_count, container, color, version, remote);
                                } else {
                                    println!("         \x1b[32m0\x1b[0m  {} {}{}\x1b[0m -> \x1b[32m{}\x1b[0m", container, color, version, remote);
                                }
                                ood += 1
                            } else {
                                if advisories.contains_key(base_crate.as_str()) {
                                    let adv_tot = advisories.get(base_crate.as_str()).unwrap().len();
                                    sav += adv_tot;
                                    let mut adv_count = format!("\x1b[41m{}\x1b[0m", adv_tot.to_string());
                                    while adv_count.len() < 19 {
                                        adv_count = format!(" {}", adv_count);
                                    }
                                    println!("{}  {} {}{}\x1b[0m", adv_count, container, color, version);
                                } else {
                                    println!("         \x1b[32m0\x1b[0m  {} {}{}\x1b[0m", container, color, version);
                                }
                                utd += 1;
                            }
                        } else {
                            println!("{}* - \x1b[35m{}\x1b[0m", container, version);
                        }
                    } else {
                        let components: Vec<&str> = line.split(" = ").collect();
                        let mut container = components[0].to_string();

                        let vcore = components[1].split('"').collect::<Vec<&str>>();
                        let mut pieces = vcore[1].split('.').collect::<Vec<&str>>();
                        println!("pieces={:?}", pieces);

                        while pieces.len() < 3 {
                            pieces.push("0");
                        }

                        let vfull: String = pieces.join(".");

                        let version = match Version::parse(vfull.as_str()) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("Failed to parse {}: {}", line, e);
                                exit(1);
                            }
                        };
                        let crate_res: Result<CrateResponse, Error> = client.get_crate(container.as_str());
                        if let Ok(response) = crate_res {
                            let mut rcore = "0.0.0".to_string();
                            for ver in response.versions {
                                let mut vnum = ver.num;

                                let mut rpieces = vnum.split('.').collect::<Vec<&str>>();

                                if rpieces.len() < 3 {
                                    rpieces.push("0");
                                }
                                vnum = rpieces.join(".");
                                let parsed = Version::parse(vnum.as_str()).unwrap();
                                let core = Version::parse(rcore.as_str()).unwrap();

                                if parsed > core {
                                    rcore = vnum;
                                }
                            }
                            let mut rpieces = rcore.split('.').collect::<Vec<&str>>();

                            if rpieces.len() < 3 {
                                rpieces.push("0");
                            }
                            let rfull: String = rpieces.join(".");
                            let remote = Version::parse(rfull.as_str()).unwrap();

                            let base_crate = container.clone();

                            while container.len() < 44 {
                                container = format!("{} ", container);
                            }

                            let mut color = "\x1b[32m";
                            if remote > version {
                                color = "\x1b[31m";
                                if advisories.contains_key(base_crate.as_str()) {
                                    let adv_tot = advisories.get(base_crate.as_str()).unwrap().len();
                                    sav += adv_tot;
                                    let mut adv_count = format!("\x1b[41m{}\x1b[0m", adv_tot.to_string());
                                    while adv_count.len() < 19 {
                                        adv_count = format!(" {}", adv_count);
                                    }
                                    println!("{}  {} {}{}\x1b[0m -> \x1b[32m{}\x1b[0m", adv_count, container, color, version, remote);
                                } else {
                                    println!("         \x1b[32m0\x1b[0m  {} {}{}\x1b[0m -> \x1b[32m{}\x1b[0m", container, color, version, remote);
                                }
                                ood += 1
                            } else {
                                if advisories.contains_key(base_crate.as_str()) {
                                    let adv_tot = advisories.get(base_crate.as_str()).unwrap().len();
                                    sav += adv_tot;
                                    let mut adv_count = format!("\x1b[41m{}\x1b[0m", adv_tot.to_string());
                                    while adv_count.len() < 19 {
                                        adv_count = format!(" {}", adv_count);
                                    }
                                    println!("{}  {} {}{}\x1b[0m", adv_count, container, color, version);
                                } else {
                                    println!("         \x1b[32m0\x1b[0m  {} {}{}\x1b[0m", container, color, version);
                                }
                                utd += 1;
                            }
                        } else {
                            println!("{}* - \x1b[35m{}\x1b[0m", container, version);
                        }
                    }
                }
            }
        }
        println!("=========================================================================");
        println!("Results: Up to date: {}   Updates available: {}   Security Advisories: {}", utd, ood, sav);
        println!("=========================================================================");
        println!("Total: {}", utd + ood);
        println!("=========================================================================");
        println!("* Crate failed to return a version result");
    } else {
        println!("\x1b[41mFATAL ERROR\x1b[0m: Unable to locate Cargo.toml file")
    }*/
}
