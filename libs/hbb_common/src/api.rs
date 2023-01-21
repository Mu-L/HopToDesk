use lazy_static::lazy_static;
use log::info;
use std::sync::Arc;
use std::fs;
use std::io::Read;
use tokio::sync::Mutex;

use crate::config::Config2;
use crate::config::Config;

const API_URI: &'static str = "https://api.hoptodesk.com/";

#[derive(Debug, Clone)]
pub struct ApiError(String);

impl<E: std::error::Error> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.to_string())
    }
}

#[derive(Default)]
struct OnceAPI {
    response: Arc<Mutex<Option<serde_json::Value>>>,
}

impl OnceAPI {
    async fn call(&self) -> Result<serde_json::Value, ApiError> {
        let mut r = self.response.lock().await;
        if let Some(r) = &*r {
            return Ok(r.clone());
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            if let Ok(mut file) = fs::File::open(&Config::path("api.json")) {
                let mut body = String::new();
                file.read_to_string(&mut body).ok();
                let ret: serde_json::Value = serde_json::from_str(&body)?;
                *r = Some(ret.clone());
                info!("api file {}", "api.json");
                return Ok(ret);
            }
        }

        let api_uri = Config2::get()
            .options
            .get("custom-api-url")
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| API_URI.to_owned());
        info!("api uri {}", api_uri);
        let body = reqwest::get(api_uri).await?.text().await?;
        let ret: serde_json::Value = serde_json::from_str(&body)?;
        *r = Some(ret.clone());
        Ok(ret)
    }

    async fn erase(&self) {
        let mut r = self.response.lock().await;
        *r = None
    }
}

lazy_static! {
    static ref ONCE: OnceAPI = OnceAPI::default();
}

pub async fn call_api() -> Result<serde_json::Value, ApiError> {
    (*ONCE).call().await
}

pub async fn erase_api() {
    (*ONCE).erase().await
}