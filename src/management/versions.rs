use crate::utilities::errors::{VerificationError, Errors};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use cargo_toml::Manifest;
use crate::utilities::terminal::output::{DisplayLine, OutputDisplayType};
use crate::management::security::SecurityDatabase;
use std::process::{Command, exit};
use crate::management::api::ApiManager;
use crate::utilities::serial::api::{Crate, CrateType, filter_wildcards};
use tokio::sync::mpsc::Sender;
use semver::{VersionReq, Version};

#[derive(Debug, Clone)]
pub struct Line {
    pub level: usize,
    pub package: Crate,
}

pub struct VersionManager {
    pub client: ApiManager,
}

impl VersionManager {
    pub fn new() -> VersionManager {
        VersionManager {
            client: ApiManager::new(),
        }
    }

    pub async fn fetch_dependencies<P: AsRef<Path>>(&self, path_to_manifest: P, output: &mut Sender<DisplayLine>, db: &SecurityDatabase, recursion: usize) -> Result<(u32, u32, u32, u32), VerificationError> {
        let (mut good, mut bad, mut insecure, mut warn): (u32, u32, u32, u32) = (0, 0, 0, 0);
        let handle = OpenOptions::new().write(true).read(true).create(false).open(path_to_manifest.as_ref());
        return if let Ok(mut file) = handle {
            let mut content_string = String::new();

            let read_result = file.read_to_string(&mut content_string);

            if read_result.is_ok() {
                let manifest: Manifest = toml::from_str(content_string.as_str()).unwrap();
                if let Some(package) = manifest.package {
                    output.send(DisplayLine::new_title(format!("Version Report: {}", package.name).as_str())).await;
                } else {
                    output.send(DisplayLine::new_title("Version Report: Unknown Package")).await;
                }
                output.send(DisplayLine::new_header()).await;
                output.send(DisplayLine::new_guide()).await;
                let tree_result = Command::new("cargo").args(&["tree", "--prefix", "depth", "--no-dedupe", "--edges", "all", "--charset", "utf8", "--color", "never"]).output();

                if let Ok(tree) = tree_result {
                    let mut processed: Vec<String> = vec![];
                    let text = String::from_utf8(tree.stdout.to_vec()).unwrap();
                    let mut index: i32 = 0;
                    for line in text.split("\n") {
                        if !line.contains("feature") && index > 0 {
                            let package = parse_line(self, line, recursion, &processed).await;
                            if recursion == 0 {
                                if package.level == 2 {
                                    (good, bad, insecure, warn) = process_dependency(package, output, db, &mut processed, good, bad, insecure, warn, true).await;
                                }
                            } else if recursion == 1 {
                                if package.level == 2 {
                                    (good, bad, insecure, warn) = process_dependency(package, output, db, &mut processed, good, bad, insecure, warn, true).await;
                                } else if package.level == 3 {
                                    (good, bad, insecure, warn) = process_dependency(package, output, db, &mut processed, good, bad, insecure, warn, false).await;
                                }
                            } else {
                                if package.level == 2 {
                                    (good, bad, insecure, warn) = process_dependency(package, output, db, &mut processed, good, bad, insecure, warn, true).await;
                                } else if package.level > 2 {
                                    (good, bad, insecure, warn) = process_dependency(package, output, db, &mut processed, good, bad, insecure, warn, false).await;
                                }
                            }
                        }
                        index += 1;
                    }
                    Ok((good, bad, insecure, warn))
                } else {
                    Err(VerificationError::new(Errors::CrateFileNotFound))
                }
            } else {
                Err(VerificationError::new(Errors::CrateFileNotFound))
            }
        } else {
            Err(VerificationError::new(Errors::CrateFileNotFound))
        };
    }
}

fn count_advisories(db: &SecurityDatabase, name: &str, local: &VersionReq) -> u16 {
    return if db.advisories.contains_key(name) {
        let advisories = db.advisories.get(name).unwrap();
        let mut applicable = 0;
        for case in advisories {
            if let Some(patch_info) = case.clone().versions {
                if let Some(patched_in) = patch_info.patched {
                    for version in patched_in {
                        if !local.matches(&Version::parse(filter_wildcards(version).to_string().as_str()).unwrap()) {
                            applicable += 1;
                        }
                    }
                } else {
                    applicable += 1;
                }
            } else {
                applicable += 1;
            }
        }
        applicable
    } else {
        0
    };
}

pub async fn parse_line(client: &VersionManager, line: &str, recursion: usize, processed: &Vec<String>) -> Line {
    let mut index = 0;
    let chars: Vec<&str> = line.split("").collect();

    let mut indices: Vec<&str> = Vec::new();

    for char in chars {
        match char {
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" => {
                indices.push(char);
                index += 1;
            }
            "" => {}
            _ => {
                break;
            }
        }
    };

    let ln = line.split_at(index);

    let lvl: usize = if let Ok(li) = ln.0.parse() {
        li
    } else {
        0
    };
    let package_info = ln.1;
    let components: Vec<&str> = package_info.split(" ").collect();
    let name = components[0];
    return if components.len() > 1 {
        if !processed.contains(&name.clone().to_string()) {
            let version = components[1].split_at(1).1;
            let mut should_request = true;
            if recursion == 0 {
                if lvl > 2 {
                    should_request = false;
                }
            } else if recursion == 1 {
                if lvl > 3 {
                    should_request = false
                }
            }
            if should_request {
                let crate_resp = client.client.get_crate(name, version).await;
                if let Ok(package) = crate_resp {
                    Line {
                        level: lvl,
                        package,
                    }
                } else {
                    Line {
                        level: lvl,
                        package: Crate {
                            crate_type: CrateType::Local,
                            name: name.to_string(),
                            version: None,
                            dependencies: vec![],
                            latest: None,
                            latest_stable: None,
                        },
                    }
                }
            } else {
                Line {
                    level: lvl,
                    package: Crate {
                        crate_type: CrateType::Local,
                        name: name.to_string(),
                        version: None,
                        dependencies: vec![],
                        latest: None,
                        latest_stable: None,
                    },
                }
            }
        } else {
            Line {
                level: lvl,
                package: Crate {
                    crate_type: CrateType::PreProcessed,
                    name: name.to_string(),
                    version: None,
                    dependencies: vec![],
                    latest: None,
                    latest_stable: None,
                },
            }
        }
    } else {
        if !processed.contains(&name.clone().to_string()) {
            Line {
                level: lvl,
                package: Crate {
                    crate_type: CrateType::PreProcessed,
                    name: name.to_string(),
                    version: None,
                    dependencies: vec![],
                    latest: None,
                    latest_stable: None,
                },
            }
        } else {
            Line {
                level: lvl,
                package: Crate {
                    crate_type: CrateType::Local,
                    name: name.to_string(),
                    version: None,
                    dependencies: vec![],
                    latest: None,
                    latest_stable: None,
                },
            }
        }
    };
}

pub async fn process_dependency(package: Line, output: &mut Sender<DisplayLine>, db: &SecurityDatabase, processed: &mut Vec<String>, mut good: u32, mut bad: u32, mut insecure: u32, mut warn: u32, is_root: bool) -> (u32, u32, u32, u32) {
    match package.package.crate_type {
        CrateType::CratesIO => {
            let local = package.package.version.clone().unwrap();
            if local.to_string() != "0.0.0".to_string() {
                let container = package.package;
                let container2 = container.clone();
                let advisories = count_advisories(db, container.name.as_str(), &local);
                processed.push(container.name.clone());
                let mut display = DisplayLine::new_crate(container.name, local.to_string(), container.latest_stable.unwrap().to_string(), advisories);

                if !is_root {
                    display.display_type = OutputDisplayType::DepEntry
                }

                if container2.is_current_unstable() || container2.is_current() {
                    good += 1;
                    display.cells[1].color = "\x1b[32m".to_string();
                    display.cells[2].color = "\x1b[32m".to_string();
                } else {
                    bad += 1;
                    display.cells[1].color = "\x1b[32m".to_string();
                    display.cells[2].color = "\x1b[32m".to_string();
                }

                if advisories > 0 {
                    insecure += 1;
                    display.cells[0].color = "\x1b[31m".to_string();
                    display.cells[1].color = "\x1b[31m".to_string();
                    display.cells[2].color = "\x1b[31m".to_string();
                    if container2.is_current_unstable() || container2.is_current() {
                        display.cells[3].color = "\x1b[31m".to_string();
                    }
                }

                output.send(display).await;
            }
        }
        CrateType::Local => {
            let local = package.package.version.clone().unwrap();
            let container = package.package;
            let container2 = container.clone();
            let advisories = count_advisories(db, container.name.as_str(), &local);
            processed.push(container.name.clone());
            let mut display = if is_root {
                DisplayLine::new_crate(container.name, local.to_string(), container.latest_stable.unwrap().to_string(), advisories)
            } else {
                DisplayLine::new_crate_dep(container.name, local.to_string(), container.latest_stable.unwrap().to_string(), advisories, "┣━")
            };

            if container2.is_current_unstable() || container2.is_current() {
                good += 1;
                display.cells[1].color = "\x1b[32m".to_string();
                display.cells[2].color = "\x1b[32m".to_string();
            } else {
                bad += 1;
                display.cells[1].color = "\x1b[32m".to_string();
                display.cells[2].color = "\x1b[32m".to_string();
            }

            if advisories > 0 {
                insecure += 1;
                display.cells[0].color = "\x1b[31m".to_string();
                display.cells[1].color = "\x1b[31m".to_string();
                display.cells[2].color = "\x1b[31m".to_string();
                if container2.is_current_unstable() || container2.is_current() {
                    display.cells[3].color = "\x1b[31m".to_string();
                }
            }

            output.send(display).await;
            warn += 1;
        }
        _ => {}
    }

    (good, bad, insecure, warn)
}