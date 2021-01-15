use crates_io_api::{SyncClient, CrateResponse, Error};
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

#[derive(Debug, Clone)]
pub struct Dependency {
    pub wildcards: Vec<char>,
    pub name: String,
    pub version: Version,
    pub remote: Version,
}

#[derive(Debug, Clone)]
pub struct Version {
    pub is_semver: bool,
    pub is_provided: bool,
    pub prefixes: Option<String>,
    pub semver: Option<semver::Version>,
    pub normal: Option<String>,
}

impl fmt::Display for Dependency {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.name, self.version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_provided {
            if self.is_semver {
                write!(f, "{}", self.semver.clone().unwrap())
            } else {
                write!(f, "{}", self.normal.clone().unwrap())
            }
        } else {
            write!(f, "N/A")
        }
    }
}

impl Dependency {
    pub fn new(name: &str, version: &str, remote: Version) -> Dependency {
        let prefixes = Regex::new(r#"[><=^*~ ]"#).unwrap();
        let mut wildcards: Vec<char> = vec!();
        let mut ver = "".to_string();

        if prefixes.is_match(version) {
            let chars: Vec<&str> = version.split("").collect();

            for character in chars {
                if prefixes.is_match(character) && character != " " {
                    let char_vec: Vec<char> = character.chars().collect();
                    wildcards.push(char_vec.first().unwrap().clone());
                } else if character != " " {
                    ver = format!("{}{}", ver, character);
                }
            }
        } else {
            let pieces: Vec<&str> = version.split(" ").collect();
            ver = pieces.join("");
        }

        let semver_parsed = semver::Version::parse(ver.as_str());

        Dependency {
            wildcards,
            name: name.to_string(),
            version: if let Ok(ver) = semver_parsed {
                Version {
                    is_semver: true,
                    is_provided: true,
                    prefixes: None,
                    semver: Some(ver),
                    normal: None,
                }
            } else {
                if format!("{}", semver_parsed.unwrap_err()) == "expected more input".to_string() {
                    let mut pieces = ver.split('.').collect::<Vec<&str>>();

                    while pieces.len() < 3 {
                        pieces.push("0");
                    }

                    let newversion = pieces.join(".");

                    let parse_attempt = semver::Version::parse(newversion.as_str());

                    if let Ok(v2) = parse_attempt {
                        Version {
                            is_semver: true,
                            is_provided: true,
                            prefixes: None,
                            semver: Some(v2),
                            normal: None,
                        }
                    } else {
                        if ver.is_empty() {
                            Version {
                                is_semver: false,
                                is_provided: false,
                                prefixes: None,
                                semver: None,
                                normal: None,
                            }
                        } else {
                            Version {
                                is_semver: false,
                                is_provided: true,
                                prefixes: None,
                                semver: None,
                                normal: Some(ver.to_string()),
                            }
                        }
                    }
                } else {
                    if ver.is_empty() {
                        Version {
                            is_semver: false,
                            is_provided: false,
                            prefixes: None,
                            semver: None,
                            normal: None,
                        }
                    } else {
                        Version {
                            is_semver: false,
                            is_provided: true,
                            prefixes: None,
                            semver: None,
                            normal: Some(ver.to_string()),
                        }
                    }
                }
            },
            remote,
        }
    }
}

pub struct CratesIOManager {
    pub client: SyncClient,
    pub dependencies: Vec<Dependency>,
    pub utd: u16,
    pub ood: u16,
    pub sav: u16,
}

impl CratesIOManager {
    pub fn new() -> CratesIOManager {
        CratesIOManager {
            client: SyncClient::new(
                "Version Checker Utility V0.1.1 (tom.b.2k2@gmail.com)",
                std::time::Duration::from_millis(100),
            ).unwrap(),
            dependencies: vec![],
            utd: 0,
            ood: 0,
            sav: 0,
        }
    }

    pub fn check_self_update(&self, output: &OutputManager) {
        let remote_result: Result<CrateResponse, Error> = self.client.get_crate("version-checker");
        if let Ok(remote) = remote_result {
            let mut remote_version = Version {
                is_semver: true,
                is_provided: true,
                prefixes: None,
                semver: Some(semver::Version::parse("0.1.2").unwrap()),
                normal: None,
            };
            let mut rcore = "0.0.0".to_string();
            for ver in remote.versions {
                let mut vnum = ver.num;

                let mut rpieces = vnum.split('.').collect::<Vec<&str>>();

                if rpieces.len() < 3 {
                    rpieces.push("0");
                }
                vnum = rpieces.join(".");
                let parsed = semver::Version::parse(vnum.as_str()).unwrap();
                let core = semver::Version::parse(rcore.as_str()).unwrap();

                if parsed > core {
                    rcore = vnum;
                }
            }
            let attempted_semver = semver::Version::parse(rcore.as_str());

            if attempted_semver.is_ok() && rcore != "0.0.0".to_string() {
                remote_version = Version {
                    is_semver: true,
                    is_provided: true,
                    prefixes: None,
                    semver: Some(attempted_semver.unwrap()),
                    normal: None,
                }
            } else if rcore != "0.0.0".to_string() {
                remote_version = Version {
                    is_semver: false,
                    is_provided: true,
                    prefixes: None,
                    semver: None,
                    normal: Some(rcore),
                }
            }


            let self_dep = Dependency::new("Self", crate::VERSION, remote_version);

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
                    output.render(DisplayLine::new_title(format!("Version Report: {}", package.name).as_str()));
                } else {
                    output.render(DisplayLine::new_title("Version Report: Unknown Package"));
                }
                output.render(DisplayLine::new_header());
                output.render(DisplayLine::new_guide());
                for entry in manifest.dependencies {
                    let (g, b, i, w) = manage_deps(self, entry, db, output, recursion, false, "");
                    good += g;
                    bad += b;
                    insecure += i;
                    warn += w;
                }

                for entry in manifest.dev_dependencies {
                    let (g, b, i, w) = manage_deps(self, entry, db, output, recursion, false, "");
                    good += g;
                    bad += b;
                    insecure += i;
                    warn += w;
                }

                for entry in manifest.build_dependencies {
                    let (g, b, i, w) = manage_deps(self, entry, db, output, recursion, false, "");
                    good += g;
                    bad += b;
                    insecure += i;
                    warn += w;
                }

                Ok((good, bad, insecure, warn))
            } else {
                Err(VerificationError::new(Errors::CrateFileNotFound))
            }
        } else {
            Err(VerificationError::new(Errors::CrateFileNotFound))
        };
    }
}

pub fn process_dependency(client: &CratesIOManager, name: String, dependency: cargo_toml::Dependency) -> Dependency {
    let remote_result: Result<CrateResponse, Error> = client.client.get_crate(name.as_str());
    let mut remote_version: Version = Version {
        is_semver: false,
        is_provided: false,
        prefixes: None,
        semver: None,
        normal: None,
    };

    if remote_result.is_ok() {
        let mut rcore = "0.0.0".to_string();
        for ver in remote_result.unwrap().versions {
            let mut vnum = ver.num;

            let mut rpieces = vnum.split('.').collect::<Vec<&str>>();

            if rpieces.len() < 3 {
                rpieces.push("0");
            }
            vnum = rpieces.join(".");
            let parsed = semver::Version::parse(vnum.as_str()).unwrap();
            let core = semver::Version::parse(rcore.as_str()).unwrap();

            if parsed > core {
                rcore = vnum;
            }
        }
        let attempted_semver = semver::Version::parse(rcore.as_str());

        if attempted_semver.is_ok() && rcore != "0.0.0".to_string() {
            remote_version = Version {
                is_semver: true,
                is_provided: true,
                prefixes: None,
                semver: Some(attempted_semver.unwrap()),
                normal: None,
            }
        } else if rcore != "0.0.0".to_string() {
            remote_version = Version {
                is_semver: false,
                is_provided: true,
                prefixes: None,
                semver: None,
                normal: Some(rcore),
            }
        }
    }

    match dependency {
        cargo_toml::Dependency::Simple(version) => {
            Dependency::new(name.as_str(), version.as_str(), remote_version)
        }
        cargo_toml::Dependency::Detailed(manifest) => {
            if let Some(version) = manifest.version {
                Dependency::new(name.as_str(), version.as_str(), remote_version)
            } else {
                Dependency::new(name.as_str(), "", remote_version)
            }
        }
    }
}

fn check_diff(local: Version, remote: Version) -> bool {
    return if local.is_semver && remote.is_semver {
        local.semver.clone().unwrap() == remote.semver.clone().unwrap()
    } else {
        false
    };
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

pub fn manage_deps(client: &CratesIOManager, entry: (String, cargo_toml::Dependency), db: &SecurityDatabase, output: &OutputManager, recursion: usize, did_recurse: bool, indenter: &str) -> (u16, u16, u16, u16) {
    let (mut good, mut bad, mut insecure, mut warn) = (0, 0, 0, 0);
    let dep: Dependency = process_dependency(&client, entry.0, entry.1);
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
        output.render(row.clone());
        let text = " ".to_string();
        row.cells[0].text = text.clone();
        row.cells[0].color = "\x1b[36m".to_string();
        row.cells[1].text = text.clone();
        row.cells[2].text = text.clone();
        row.cells[3].text = text;
        row.display_type = OutputDisplayType::Entry;
    }

    output.render(row);

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