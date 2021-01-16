use semver::{VersionReq, Version};

#[derive(Debug, Clone)]
pub struct Crate {
    pub name: String,
    pub version: VersionReq,
    pub dependencies: Vec<Crate>,
    pub latest: VersionReq,
    pub latest_stable: VersionReq
}

impl Crate {
    pub fn is_current(&self) -> bool {
        let max = self.latest_stable.to_string();

        self.version.matches(&Version::parse(max.as_str()).unwrap())
    }
    pub fn is_current_unstable(&self) -> bool {
        let max = self.latest.to_string();

        self.version.matches(&Version::parse(max.as_str()).unwrap())
    }
}

pub fn highest(v: &VersionReq) {
        println!("{}", v);
    }