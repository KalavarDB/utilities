use crates_io_api::SyncClient;
use crate::utilities::errors::{VerificationError, Errors};
use std::fs::OpenOptions;
use std::io::Read;

#[derive(Debug)]
pub struct Dependency {
    pub name: String,
    pub version: Version,
}

#[derive(Debug)]
pub struct Version {
    pub is_semver: bool,
    pub semver: Option<semver::Version>,
    pub normal: Option<String>,
}

impl Dependency {
    pub fn new(name: &str, version: &str) -> Dependency {
        let semver_parsed = semver::Version::parse(version);

        Dependency {
            name: name.to_string(),
            version: if let Ok(ver) = semver_parsed {
                Version {
                    is_semver: true,
                    semver: Some(ver),
                    normal: None,
                }
            } else {
                if format!("{}", semver_parsed.unwrap_err()) == "expected more input".to_string() {
                    let mut pieces = version.split('.').collect::<Vec<&str>>();

                    while pieces.len() < 3 {
                        pieces.push("0");
                    }

                    let newversion = pieces.join(".");

                    let parse_attempt = semver::Version::parse(newversion.as_str());

                    if let Ok(v2) = parse_attempt {
                        Version {
                            is_semver: true,
                            semver: Some(v2),
                            normal: None,
                        }
                    } else {
                        Version {
                            is_semver: false,
                            semver: None,
                            normal: Some(version.to_string()),
                        }
                    }
                } else {
                    Version {
                        is_semver: false,
                        semver: None,
                        normal: Some(version.to_string()),
                    }
                }
            },
        }
    }
}

// Define the line ending of the current system, if unix it is "\n" if windows it is "\r\n", this is important when reading and writing files
#[cfg(windows)]
const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &str = "\n";

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
                "my_bot (help@my_bot.com)",
                std::time::Duration::from_millis(100),
            ).unwrap(),
            dependencies: vec![],
            utd: 0,
            ood: 0,
            sav: 0,
        }
    }

    pub fn fetch_deps(&mut self) -> Result<(), VerificationError> {
        let handle = OpenOptions::new().write(true).read(true).create(false).open("./Cargo.toml");
        return if let Ok(mut file) = handle {
            let mut in_deps = false;

            let mut content_string = String::new();

            let read_result = file.read_to_string(&mut content_string);

            if read_result.is_ok() {
                for line in content_string.split(LINE_ENDING) {
                    if !line.is_empty() {
                        if line.starts_with('[') && line.ends_with(']') && !line.contains("dependencies") {
                            in_deps = false;
                        } else if line == "[dependencies]" {
                            in_deps = true;
                        } else if in_deps {
                            if line.contains('{') {
                                let components: Vec<&str> = line.split(" = {").collect();
                                if components.len() == 2 {
                                    let name = components[0];
                                    let mut version = "".to_string();
                                    let keypairs: Vec<&str> = components[1].split(",").collect();

                                    for key in keypairs {
                                        if key.contains("version") {
                                            let pair: Vec<&str> = key.split(" = ").collect();
                                            version = pair[1].replace('"', "");
                                        }
                                    }
                                    self.dependencies.push(Dependency::new(name, version.as_str()));
                                }
                            } else {
                                let components: Vec<&str> = line.split(" = ").collect();
                                if components.len() == 2 {
                                    let version = components[1].replace('"', "");
                                    self.dependencies.push(Dependency::new(components[0], version.as_str()));
                                }
                            }
                        }
                    }
                }

                Ok(())
            } else {
                Err(VerificationError::new(Errors::CrateFileNotFound))
            }
        } else {
            Err(VerificationError::new(Errors::CrateFileNotFound))
        };
    }
}