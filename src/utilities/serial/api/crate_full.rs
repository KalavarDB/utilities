use semver::{VersionReq, Version};

#[derive(Debug, Clone)]
pub enum CrateType {
    CratesIO,
    Local,
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
                let max = self.latest_stable.clone().unwrap().to_string();
                println!("max: {}", max);
                self.version.clone().unwrap().matches(&Version::parse(max.as_str()).unwrap())
            }
            CrateType::Local => {
                true
            }
        };
    }
    pub fn is_current_unstable(&self) -> bool {
        return match self.crate_type {
            CrateType::CratesIO => {
                let max = self.latest_stable.clone().unwrap().to_string();
                self.version.clone().unwrap().matches(&Version::parse(max.as_str()).unwrap())
            }
            CrateType::Local => {
                true
            }
        };
    }
}

pub fn highest(v: &VersionReq) {
    println!("{}", v);
}