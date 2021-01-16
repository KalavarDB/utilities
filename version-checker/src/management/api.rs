use serde_json;
use crate::utilities::serial::api::*;
use reqwest::{Client, ClientBuilder};
use crate::utilities::errors::{VerificationError, Errors};


pub struct ApiManager {
    client: Client
}

impl ApiManager {
    pub fn new() -> ApiManager {
        ApiManager {
            client: ClientBuilder::new().user_agent(format!("Kalavar Version Utility v{} <Thomas B. | tom.b.2k2@gmail.com>", crate::VERSION).as_str()).build().unwrap()
        }
    }

    pub async fn get_crate(&self, name: &str, version: &str) -> Result<Crate, VerificationError> {
        let response = self.client.get(format!("https://crates.io/api/v1/crates/{}", name)).send().await;
        return if let Ok(resp_inner) = response {
            let parse_attempt: reqwest::Result<CrateResponse> = resp_inner.json().await;
            if let Ok(crate_resp) = parse_attempt {
                Ok(crate_resp.into_crate(version))
            } else {
                Err(VerificationError::new(Errors::CrateParseFailed))
            }
        } else {
            Err(VerificationError::new(Errors::CrateNotAvailable))
        }
    }
}