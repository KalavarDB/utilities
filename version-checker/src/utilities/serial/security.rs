use serde_derive::Deserialize;

// TOML security advisory, found in the MD file
#[derive(Deserialize)]
pub struct Advisory {
    pub name: Option<String>,
    pub content_body: Option<String>,

    pub id: Option<String>,
    pub package: Option<String>,
    pub date: Option<String>,
    pub url: Option<String>,
    pub categories: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
    pub aliases: Option<Vec<String>>,
    pub cvss: Option<String>,

    pub versions: Option<Version>,
    pub affected: Option<Affected>,
}

#[derive(Deserialize)]
pub struct Version {
    pub patched: Option<Vec<String>>,
    pub unaffected: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct Affected {
    pub arch: Option<Vec<String>>,
    pub os: Option<Vec<String>>,
}