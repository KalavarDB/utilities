use semver::VersionReq;

pub struct Crate {
    pub name: String,
    pub version: VersionReq,
    pub dependencies: Vec<Crate>,
    pub latest: VersionReq,
    pub latest_stable: VersionReq
}

impl Crate {
    pub fn is_current(&self) -> bool {
        let max = self.latest_stable.max().to_string();

        self.version.matches()
    }
    pub fn is_current_unstable(&self) -> bool {

    }
}