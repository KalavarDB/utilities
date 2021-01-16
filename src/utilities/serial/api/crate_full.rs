use semver::{VersionReq, Version};
use regex::Regex;

#[derive(Debug, Clone)]
pub enum CrateType {
    CratesIO,
    Local,
    PreProcessed
}

#[derive(Debug, Clone)]
pub struct Crate {
    pub crate_type: CrateType,
    pub name: String,
    pub version: Option<VersionReq>,
    pub dependencies: Vec<Crate>,
    pub latest: Option<VersionReq>,
    pub latest_stable: Option<VersionReq>,
}

impl Crate {
    pub fn is_current(&self) -> bool {
        return match self.crate_type {
            CrateType::CratesIO => {
                let max = filter_wildcards(self.latest_stable.clone().unwrap());
                self.version.clone().unwrap().matches(&max)
            }
            CrateType::Local => {
                true
            }
            _ => {
                true
            }
        };
    }
    pub fn is_current_unstable(&self) -> bool {
        return match self.crate_type {
            CrateType::CratesIO => {
                let max = filter_wildcards(self.latest.clone().unwrap());
                self.version.clone().unwrap().matches(&max)
            }
            CrateType::Local => {
                true
            }
            _ => {
                true
            }
        };
    }
}

pub fn filter_wildcards<A: ToString>(v: A) -> Version {
    let prefixes = Regex::new(r#"[><=^*~ ]"#).unwrap();
    let mut wildcards: Vec<char> = vec!();
    let mut ver = "".to_string();
    let version = v.to_string();
    if version == "Not Applicable" {
        semver::Version::parse("0.0.0").unwrap()
    } else {
        let mut pieces: Vec<&str> = vec![];
        if prefixes.is_match(version.as_str()) {
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
            pieces = version.split(" ").collect();
            ver = pieces.join("");
        }

        let veclone = ver.clone();

        pieces = veclone.split(",").collect();

        ver = pieces[0].to_string();

        pieces = ver.split(".").collect();

        while pieces.len() < 3 {
            pieces.push("0");
        }

        ver = pieces.join(".");


        semver::Version::parse(ver.as_str()).unwrap()
    }
}