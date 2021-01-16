use serde_derive::Deserialize;
use semver::{VersionReq, Compat};
use super::crate_full::*;
use crate::utilities::errors::{VerificationError, Errors};

#[derive(Debug, Clone, Deserialize)]
pub struct CrateResponse {
    #[serde(rename = "crate")]
    pub package: PreCrate,
    pub version: Vec<PreVersion>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreCrate {
    pub name: String,
    pub keywords: Vec<String>,
    pub max_version: String,
    pub max_stable_version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreVersion {
    pub num: String,
    pub links: VersionLinks,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionLinks {
    pub dependencies: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DependencyResponse {
    pub dependencies: Vec<PreDependency>
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreDependency {
    pub crate_id: String,
    pub req: String,
    pub optional: bool,
    pub kind: String,
}

impl CrateResponse {
    pub fn into_crate(self, local: &str) -> Result<Crate, VerificationError> {
        let local_ver_parse = VersionReq::parse_compat(local, Compat::Cargo);
        let max_parse = VersionReq::parse_compat(self.package.max_version.as_str(), Compat::Cargo);
        let max_stable_parse = VersionReq::parse_compat(self.package.max_stable_version.as_str(), Compat::Cargo);

        return if let Ok(localver) = local_ver_parse {
            if let Ok(max) = max_parse {
                if let Ok(max_stable) = max_stable_parse {
                    Ok(Crate {
                        name: self.package.name,
                        version: localver,
                        dependencies: vec![],
                        latest: max,
                        latest_stable: max_stable,
                    })
                } else {
                    Err(VerificationError::new(Errors::VersionUnacceptable))
                }
            } else {
                Err(VerificationError::new(Errors::VersionUnacceptable))
            }
        } else {
            Err(VerificationError::new(Errors::VersionUnacceptable))
        };
    }
}
