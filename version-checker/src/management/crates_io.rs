use crates_io_api::{SyncClient, CrateResponse, Error};
use crate::utilities::errors::{VerificationError, Errors};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use cargo_toml::{Manifest, DependencyDetail};
use std::fmt;
use serde::__private::Formatter;
use regex::Regex;
use crate::utilities::terminal::output::{DisplayLine, OutputManager};

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

    pub fn fetch_dependencies<P: AsRef<Path>>(&self, path_to_manifest: P, output: &OutputManager) -> Result<(u16, u16, u16, u16), VerificationError> {
        let (mut good, mut bad, mut insecure, mut warn) = (0, 0, 0, 0);
        let handle = OpenOptions::new().write(true).read(true).create(false).open(path_to_manifest.as_ref());
        return if let Ok(mut file) = handle {
            let mut content_string = String::new();

            let read_result = file.read_to_string(&mut content_string);

            if read_result.is_ok() {
                let manifest: Manifest = toml::from_str(content_string.as_str()).unwrap();

                for entry in manifest.dependencies {
                    let dep: Dependency = process_dependency(self, entry.0, entry.1);

                    let mut row = DisplayLine::new_crate(dep.clone());

                    if !dep.version.is_provided {
                        warn += 1;
                        row.cells[0].color = "\x1b[33m".to_string();
                        row.cells[1].color = "\x1b[33m".to_string();
                        row.cells[2].color = "\x1b[33m".to_string();
                        row.cells[3].color = "\x1b[33m".to_string();
                    }

                    output.render(row);
                }

                for entry in manifest.dev_dependencies {
                    let dep: Dependency = process_dependency(self, entry.0, entry.1);

                    let mut row = DisplayLine::new_crate(dep.clone());

                    if !dep.version.is_provided {
                        warn += 1;
                        row.cells[0].color = "\x1b[33m".to_string();
                        row.cells[1].color = "\x1b[33m".to_string();
                        row.cells[2].color = "\x1b[33m".to_string();
                        row.cells[3].color = "\x1b[33m".to_string();
                    }

                    output.render(row);
                }

                for entry in manifest.build_dependencies {
                    let dep: Dependency = process_dependency(self, entry.0, entry.1);

                    let mut row = DisplayLine::new_crate(dep.clone());

                    if !dep.version.is_provided {
                        warn += 1;
                        row.cells[0].color = "\x1b[33m".to_string();
                        row.cells[1].color = "\x1b[33m".to_string();
                        row.cells[2].color = "\x1b[33m".to_string();
                        row.cells[3].color = "\x1b[33m".to_string();
                    }

                    output.render(row);
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
                if let Some(path) = manifest.path {
                    Dependency::new(name.as_str(), "", remote_version)
                } else {
                    Dependency::new(name.as_str(), "", remote_version)
                }
            }
        }
    }
}

fn check_diff(local: Version, remote: Version) -> bool {
    false
}