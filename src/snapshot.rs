use crate::local_browser::{
    BrowserCookie, ReadBrowserCookiesInput, cookie_domain_count, filter_cookie_domains,
    read_browser_cookies,
};
use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};
use serde::Serialize;
use std::{
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct CaptureInput {
    pub browser: Option<String>,
    pub user_data_dir: Option<PathBuf>,
    pub profile_directory: Option<String>,
    pub domains: Vec<String>,
}

pub struct CapturedSnapshot {
    pub brand_id: &'static str,
    pub profile_directory: String,
    pub user_data_dir: PathBuf,
    pub cookies: Vec<BrowserCookie>,
    pub domain_count: usize,
    pub payload: Vec<u8>,
}

#[derive(Serialize)]
struct PortableBrowserProfileSnapshot<'a> {
    version: &'static str,
    source: PortableBrowserProfileSnapshotSource<'a>,
    cookies: &'a [BrowserCookie],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortableBrowserProfileSnapshotSource<'a> {
    browser_family: &'static str,
    browser_brand: &'a str,
    capture_method: &'static str,
    platform: &'static str,
    captured_at: u64,
}

pub fn capture(input: CaptureInput) -> Result<CapturedSnapshot> {
    let read = read_browser_cookies(ReadBrowserCookiesInput {
        browser: input.browser,
        user_data_dir: input.user_data_dir,
        profile_directory: input.profile_directory,
    })?;
    let cookies = filter_cookie_domains(read.cookies, &input.domains);
    if cookies.is_empty() {
        anyhow::bail!(
            "no syncable cookies found for the selected local browser profile and domain scope"
        );
    }
    let domain_count = cookie_domain_count(&cookies);
    let snapshot = PortableBrowserProfileSnapshot {
        version: "portable-cookies-v1",
        source: PortableBrowserProfileSnapshotSource {
            browser_family: "chromium",
            browser_brand: read.brand.id_text,
            capture_method: "cdp",
            platform: platform_name(),
            captured_at: now_millis(),
        },
        cookies: &cookies,
    };
    let payload = gzip_json(&snapshot)?;
    Ok(CapturedSnapshot {
        brand_id: read.brand.id_text,
        profile_directory: read.profile_directory,
        user_data_dir: read.user_data_dir,
        cookies,
        domain_count,
        payload,
    })
}

fn gzip_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    serde_json::to_writer(&mut encoder, value)?;
    encoder.flush()?;
    encoder
        .finish()
        .context("failed to gzip browser profile snapshot")
}

fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
