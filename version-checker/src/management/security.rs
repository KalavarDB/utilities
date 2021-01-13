use std::env::current_exe;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::process::exit;
use std::io::{Write, Read};

use reqwest::blocking::{Client, ClientBuilder};

use crate::utilities::errors::Errors;
use crate::utilities::serial::security::Advisory;


pub struct SecurityDatabase {
    pub client: Client,
    pub advisories: HashMap<String, Advisory>,
}

impl SecurityDatabase {
    pub fn new() -> SecurityDatabase {
        SecurityDatabase {
            client: ClientBuilder::new().user_agent("Kalavar Version Utility v1.0 <Thomas B. | tom.b.2k2@gmail.com>").build().unwrap(),
            advisories: HashMap::new(),
        }
    }

    pub fn update(&mut self) -> Result<(), Errors> {
        let mut dirbytes: Vec<u8> = Vec::new();
        let _ = self.client.get("https://github.com/RustSec/advisory-db/archive/master.zip").send().unwrap().read_to_end(&mut dirbytes);

        let exe_dir = current_exe().unwrap().as_os_str().to_str().unwrap().to_string();

        let mut home_dir_vec = exe_dir.split('/').collect::<Vec<&str>>();
        home_dir_vec.pop();
        let path = format!("{}/security.zip", home_dir_vec.join("/"));

        let e = OpenOptions::new().write(true).read(true).create(true).open(path.as_str());

        return if e.is_err() {
            Err(Errors::DBUpdateFailed)
        } else {
            let mut db = e.unwrap();

            let write_status = db.write_all(dirbytes.as_slice());
            if write_status.is_ok() {
                let _ = db.flush();

                let repo = zip::read::ZipArchive::new(&mut db);

                if let Ok(mut zipped) = repo {
                    let base = "advisory-db-master/crates/";
                    let paths: Vec<&str> = zipped.file_names().collect::<Vec<&str>>().clone();
                    for path in paths {
                        if path.contains(base) {
                            let hostdir = path.split(base).collect::<Vec<&str>>();
                            let parts = hostdir[1].split('/').collect::<Vec<&str>>();
                            let crate_name = parts[0];
                            if parts.len() > 1 {
                                let file = parts[1];
                                if !file.is_empty() {

                                    let advice = zipped.by_name(file);
                                    if advice.is_ok() {
                                        let mut handle = advice.unwrap();
                                        let mut bytes: Vec<u8> = vec!();

                                        let read_result = handle.read_to_end(&mut bytes);

                                        if read_result.is_ok() {
                                            println!("{}", String::from_utf8(bytes).unwrap());
                                            exit(1);
                                        } else {
                                            println!("Unable to read file at: {}", path);
                                            exit(1);
                                            //Err(Errors::DBUnreadable)
                                        }

                                    } else {
                                        println!("Err: Unable to locate file in zip folder");
                                    }
                                    // if advisories.contains_key(crate_name) {
                                    //     advisories.get_mut(crate_name).unwrap().push(file);
                                    // } else {
                                    //     advisories.insert(crate_name, vec![file]);
                                    // }
                                }
                            }
                        }
                        // advisories.
                    }
                    Ok(())
                } else {
                    Err(Errors::DBUnreadable)
                }
            } else {
                Err(Errors::DBUnreadable)
            }
        }
    }
}