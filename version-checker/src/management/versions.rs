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

pub struct VersionManager {
    pub client: ApiManager,
}

impl VersionManager {
    pub fn new() -> VersionManager {
        VersionManager {
            client: ApiManager::new(),
        }
    }

    pub async fn check_self_update(&self, output: &OutputManager) {
        let remote_result: Result<Crate, VerificationError> = self.client.get_crate("version-checker", ).await;
        if let Ok(remote) = remote_result {

            if self_dep.version.is_semver && self_dep.remote.is_semver {
                if self_dep.version.semver.clone().unwrap() < self_dep.remote.semver.clone().unwrap() {
                    output.warn_update(self_dep.version, self_dep.remote);
                    println!();
                }
            }
        }
    }

    pub fn fetch_dependencies<P: AsRef<Path>>(&self, path_to_manifest: P, output: &OutputManager, db: &SecurityDatabase, recursion: usize) -> Result<(u16, u16, u16, u16), VerificationError> {
        let (mut good, mut bad, mut insecure, mut warn) = (0, 0, 0, 0);
        let handle = OpenOptions::new().write(true).read(true).create(false).open(path_to_manifest.as_ref());
        return if let Ok(mut file) = handle {
            let mut content_string = String::new();

            let read_result = file.read_to_string(&mut content_string);

            if read_result.is_ok() {
                let manifest: Manifest = toml::from_str(content_string.as_str()).unwrap();
                if let Some(package) = manifest.package {
                    output::render(DisplayLine::new_title(format!("Version Report: {}", package.name).as_str()));
                } else {
                    output::render(DisplayLine::new_title("Version Report: Unknown Package"));
                }
                output::render(DisplayLine::new_header());
                output::render(DisplayLine::new_guide());

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

fn count_advisories(db: &SecurityDatabase, name: &str, local: &Version) -> u16 {
    return if db.advisories.contains_key(name) {
        let advisories = db.advisories.get(name).unwrap();
        let mut applicable = 0;
        for case in advisories {
            if let Some(patch_info) = case.clone().versions {
                if let Some(patched_in) = patch_info.patched {
                    for version in patched_in {
                        let prefixes = Regex::new(r#"[><=^*~ ]"#).unwrap();
                        let mut ver = "".to_string();

                        if prefixes.is_match(version.as_str()) {
                            let chars: Vec<&str> = version.split("").collect();

                            for character in chars {
                                if !prefixes.is_match(character) && character != " " {
                                    ver = format!("{}{}", ver, character);
                                }
                            }
                        } else {
                            let pieces: Vec<&str> = version.split(" ").collect();
                            ver = pieces.join("");
                        }
                        let parse_attempt = semver::Version::parse(ver.as_str());

                        if let Ok(parsed) = parse_attempt {
                            if local.is_semver {
                                if parsed > local.semver.clone().unwrap() {
                                    applicable += 1;
                                }
                            } else {
                                applicable += 1;
                            }
                        } else {
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

pub fn manage_deps(client: &VersionManager, entry: (String, cargo_toml::Dependency), db: &SecurityDatabase, output: &OutputManager, recursion: usize, did_recurse: bool, indenter: &str) -> (u16, u16, u16, u16) {
    let (mut good, mut bad, mut insecure, mut warn) = (0, 0, 0, 0);
    let count = count_advisories(db, dep.name.as_str(), &dep.version);
    let mut row = if !did_recurse {
        DisplayLine::new_crate(dep.clone(), &count)
    } else {
        DisplayLine::new_crate_dep(dep.clone(), &count, indenter)
    };

    if !dep.version.is_provided {
        warn += 1;
        row.cells[0].color = "\x1b[33m".to_string();
        row.cells[1].color = "\x1b[33m".to_string();
        row.cells[2].color = "\x1b[33m".to_string();
        row.cells[3].color = "\x1b[33m".to_string();
    }

    let up_to_date = check_diff(dep.version.clone(), dep.remote);

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
        output::render(row.clone());
        let text = " ".to_string();
        row.cells[0].text = text.clone();
        row.cells[0].color = "\x1b[36m".to_string();
        row.cells[1].text = text.clone();
        row.cells[2].text = text.clone();
        row.cells[3].text = text;
        row.display_type = OutputDisplayType::Entry;
    }

    output::render(row);

    if recursion > 0 {
        let crate_deps: Result<Vec<crates_io_api::Dependency>, Error> = client.client.crate_dependencies(dep.name.as_str(), dep.version.to_string().as_str());

        if let Ok(dependencies) = crate_deps {
            for index in 0..dependencies.len() {
                let dependency = dependencies[index].clone();
                let (g, b, i, w) = if index == dependencies.len() - 1 {
                    manage_deps(client, (dependency.crate_id.clone(), cargo_toml::Dependency::Simple(dependency.req)), db, output, 0, true, "┗━")
                } else {
                    manage_deps(client, (dependency.crate_id.clone(), cargo_toml::Dependency::Simple(dependency.req)), db, output, 0, true, "┣━")
                };
                good += g;
                bad += b;
                insecure += i;
                warn += w;
            }
        }
    }

    (good, bad, insecure, warn)
}