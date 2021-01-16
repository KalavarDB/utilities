use crate::utilities::errors::{VerificationError, Errors};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use cargo_toml::Manifest;
use std::fmt;
use serde::__private::Formatter;
use regex::Regex;
use crate::utilities::terminal::output::{DisplayLine, OutputManager, OutputDisplayType};
use crate::management::security::SecurityDatabase;
use std::process::Command;
use crate::management::api::ApiManager;
use crate::utilities::serial::api::Crate;
use tokio::sync::mpsc::Sender;
use semver::{VersionReq, Version};

pub struct VersionManager {
    pub client: ApiManager,
}

impl VersionManager {
    pub fn new() -> VersionManager {
        VersionManager {
            client: ApiManager::new(),
        }
    }

    pub async fn fetch_dependencies<P: AsRef<Path>>(&self, path_to_manifest: P, output: &mut Sender<DisplayLine>, db: &SecurityDatabase, recursion: usize) -> Result<(u16, u16, u16, u16), VerificationError> {
        let (mut good, mut bad, mut insecure, mut warn) = (0, 0, 0, 0);
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

                let tree_result = Command::new("cargo").args(&["tree", "--no-dedupe", "--edges", "all"]).output();

                if let Ok(tree) = tree_result {
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
                        if !local.matches(&Version::parse(version.as_str()).unwrap()) {
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

pub async fn manage_deps(client: &VersionManager, dep: Crate, db: &SecurityDatabase, output: &mut Sender<DisplayLine>, recursion: usize, did_recurse: bool, indenter: &str) -> (u16, u16, u16, u16) {
    let (mut good, mut bad, mut insecure, mut warn) = (0, 0, 0, 0);
    let count = count_advisories(db, dep.name.as_str(), &dep.version);
    let mut row = if !did_recurse {
        DisplayLine::new_crate(dep.clone(), &count)
    } else {
        DisplayLine::new_crate_dep(dep.clone(), &count, indenter)
    };

    // if !dep.version. {
    //     warn += 1;
    //     row.cells[0].color = "\x1b[33m".to_string();
    //     row.cells[1].color = "\x1b[33m".to_string();
    //     row.cells[2].color = "\x1b[33m".to_string();
    //     row.cells[3].color = "\x1b[33m".to_string();
    // }

    let up_to_date = dep.is_current() || dep.is_current_unstable();

    if !up_to_date {
        bad += 1;
        row.cells[1].color = "\x1b[33m".to_string();
        row.cells[2].color = "\x1b[33m".to_string();
        row.cells[3].color = "\x1b[32m".to_string();
    } else {
        good += 1;
        row.cells[2].color = "\x1b[32m".to_string();
        row.cells[3].color = "\x1b[32m".to_string();
    }

    if count > 0 {
        insecure += count;
        row.cells[0].color = "\x1b[31m".to_string();
        row.cells[1].color = "\x1b[31m".to_string();
        row.cells[2].color = "\x1b[31m".to_string();

        if up_to_date {
            row.cells[3].color = "\x1b[31m".to_string();
        }
    }

    if did_recurse && indenter == "┗━" {
        output.send(row.clone()).await;
        let text = " ".to_string();
        row.cells[0].text = text.clone();
        row.cells[0].color = "\x1b[36m".to_string();
        row.cells[1].text = text.clone();
        row.cells[2].text = text.clone();
        row.cells[3].text = text;
        row.display_type = OutputDisplayType::Entry;
    }

    output.send(row).await;

    // if recursion > 0 {
    //     let crate_deps: Result<Vec<crates_io_api::Dependency>, Error> = client.client.crate_dependencies(dep.name.as_str(), dep.version.to_string().as_str());
    //
    //     if let Ok(dependencies) = crate_deps {
    //         for index in 0..dependencies.len() {
    //             let dependency = dependencies[index].clone();
    //             let (g, b, i, w) = if index == dependencies.len() - 1 {
    //                 manage_deps(client, (dependency.crate_id.clone(), cargo_toml::Dependency::Simple(dependency.req)), db, output, 0, true, "┗━")
    //             } else {
    //                 manage_deps(client, (dependency.crate_id.clone(), cargo_toml::Dependency::Simple(dependency.req)), db, output, 0, true, "┣━")
    //             };
    //             good += g;
    //             bad += b;
    //             insecure += i;
    //             warn += w;
    //         }
    //     }
    // }

    (good, bad, insecure, warn)
}