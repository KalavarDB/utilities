use std::env::current_exe;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Write, Read};

use regex::Regex;
use reqwest::{Client, ClientBuilder};

use crate::utilities::errors::{Errors, VerificationError};
use crate::utilities::serial::security::ParentalAdvisory;


pub struct SecurityDatabase {
    pub client: Client,
    pub advisories: HashMap<String, Vec<ParentalAdvisory>>,
}

impl SecurityDatabase {
    pub fn new() -> SecurityDatabase {
        SecurityDatabase {
            client: ClientBuilder::new().user_agent(format!("Kalavar Version Utility v{} <Thomas B. | tom.b.2k2@gmail.com>", crate::VERSION).as_str()).build().unwrap(),
            advisories: HashMap::new(),
        }
    }

    pub async fn update(&mut self) -> Result<(), VerificationError> {
        let dirbytes: Vec<u8> = self.client.get("https://github.com/RustSec/advisory-db/archive/master.zip").send().await.unwrap().bytes().await.unwrap().as_ref().to_vec();

        let exe_dir = current_exe().unwrap().as_os_str().to_str().unwrap().to_string();

        let mut home_dir_vec = exe_dir.split('/').collect::<Vec<&str>>();
        home_dir_vec.pop();
        let path = format!("{}/security.zip", home_dir_vec.join("/"));

        let e = OpenOptions::new().write(true).read(true).create(true).open(path.as_str());

        return if e.is_err() {
            Err(VerificationError::new(Errors::DBUpdateFailed))
        } else {
            let mut db = e.unwrap();
            let frontmatter_matcher = Regex::new(r#"`{3}toml(.*[\n])*`{3}"#).unwrap();
            let frontmatter_replacer = Regex::new(r#"`{3}\n|`{3}toml\n"#).unwrap();
            let write_status = db.write_all(dirbytes.as_slice());
            if write_status.is_ok() {
                let _ = db.flush();

                let repo = zip::read::ZipArchive::new(&mut db);

                if let Ok(zipped) = repo {
                    let mut file_clone = OpenOptions::new().write(true).read(true).create(true).open(path.as_str()).unwrap();
                    let mut repo_clone = zip::read::ZipArchive::new(&mut file_clone).unwrap();
                    let base = "advisory-db-master";
                    let paths: Vec<&str> = zipped.file_names().collect::<Vec<&str>>().clone();
                    for path in paths {
                        if path.contains(base) && path.ends_with(".md") {
                            let hostdir = path.split(base).collect::<Vec<&str>>();
                            let parts = hostdir[1].split('/').collect::<Vec<&str>>();
                            if parts.len() > 1 {
                                let file = parts[1];
                                if !file.is_empty() {
                                    let advice = repo_clone.by_name(path);
                                    if advice.is_ok() {
                                        let mut handle = advice.unwrap();
                                        let mut bytes: Vec<u8> = vec!();

                                        let read_result = handle.read_to_end(&mut bytes);

                                        if read_result.is_ok() {
                                            let text = String::from_utf8(bytes).unwrap();
                                            let frm_cat = frontmatter_matcher.captures(text.as_str());
                                            if frm_cat.is_some() {
                                                let frontmatter = frontmatter_replacer.replace_all(frm_cat.unwrap().get(0).unwrap().as_str(), "").to_string().replace("```", "");
                                                let body = frontmatter_matcher.replace(text.as_str(), "").to_string();

                                                let parse_result: Result<ParentalAdvisory, toml::de::Error> = toml::from_str(frontmatter.as_str());

                                                if parse_result.is_ok() {
                                                    let mut advisory = parse_result.unwrap();
                                                    let cloned = advisory.clone();
                                                    advisory.body = Some(body);

                                                    let crate_name = cloned.advisory.unwrap().package.unwrap();

                                                    if self.advisories.contains_key(crate_name.as_str()) {
                                                        self.advisories.get_mut(crate_name.as_str()).unwrap();
                                                    } else {
                                                        let vector: Vec<ParentalAdvisory> = vec![advisory];
                                                        self.advisories.insert(crate_name, vector);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        println!("Err: Unable to locate file in zip folder");
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                } else {
                    Err(VerificationError::new(Errors::DBUnreadable))
                }
            } else {
                Err(VerificationError::new(Errors::DBUnreadable))
            }
        };
    }
}