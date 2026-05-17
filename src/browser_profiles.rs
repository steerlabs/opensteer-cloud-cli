use crate::local_browser::list_local_profiles;
use crate::snapshot::{self, CaptureInput};
use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};

const PROFILE_IMPORT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const PROFILE_IMPORT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Subcommand)]
pub enum ProfileCommands {
    /// List cloud browser profiles.
    List,
    /// Create a cloud browser profile.
    Create { name: Vec<String> },
    /// Show one cloud browser profile.
    Inspect { profile: String },
    /// Archive one cloud browser profile.
    Archive { profile: String },
    /// Sync local browser cookies into a cloud browser profile.
    Sync {
        /// Cloud profile id, prefix, or name.
        profile: String,
        /// Local Chromium browser: chrome, chrome-canary, edge, brave, vivaldi, chromium, or helium.
        #[arg(long)]
        browser: Option<String>,
        /// Local Chromium user-data directory.
        #[arg(long)]
        user_data_dir: Option<PathBuf>,
        /// Local Chromium profile directory, such as Default or Profile 2.
        #[arg(long)]
        profile_directory: Option<String>,
        /// Only sync cookies for this domain or subdomains. Repeat for multiple domains.
        #[arg(long = "domain")]
        domains: Vec<String>,
    },
    /// List local Chromium profiles available for sync.
    Local {
        /// Local Chromium browser filter.
        #[arg(long)]
        browser: Option<String>,
    },
}

pub async fn handle(command: ProfileCommands, base_url: &str, access_token: String) -> Result<()> {
    let client = ProfileApiClient::new(base_url, access_token);
    match command {
        ProfileCommands::List => profile_list(&client).await,
        ProfileCommands::Create { name } => profile_create(&client, &name.join(" ")).await,
        ProfileCommands::Inspect { profile } => profile_inspect(&client, &profile).await,
        ProfileCommands::Archive { profile } => profile_archive(&client, &profile).await,
        ProfileCommands::Sync {
            profile,
            browser,
            user_data_dir,
            profile_directory,
            domains,
        } => {
            profile_sync(
                &client,
                SyncCommandInput {
                    profile,
                    browser,
                    user_data_dir,
                    profile_directory,
                    domains,
                },
            )
            .await
        }
        ProfileCommands::Local { browser } => profile_local(browser.as_deref()),
    }
}

pub fn requires_cloud_auth(command: &ProfileCommands) -> bool {
    !matches!(command, ProfileCommands::Local { .. })
}

struct SyncCommandInput {
    profile: String,
    browser: Option<String>,
    user_data_dir: Option<PathBuf>,
    profile_directory: Option<String>,
    domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfileListResponse {
    profiles: Vec<BrowserProfileDescriptor>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfileDescriptor {
    profile_id: String,
    name: String,
    status: String,
    cookie_count: Option<u64>,
    domain_count: Option<u64>,
    cookie_domains: Option<Vec<String>>,
    latest_revision: Option<u64>,
    active_session_id: Option<String>,
    last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfileImportCreateResponse {
    import_id: String,
    upload_url: String,
    max_upload_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfileImportDescriptor {
    import_id: String,
    profile_id: String,
    status: String,
    revision: Option<u64>,
    error: Option<String>,
    snapshot_summary: Option<BrowserProfileImportSnapshotSummary>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfileImportSnapshotSummary {
    cookie_count: u64,
    domain_count: u64,
    cookie_domains: Option<Vec<String>>,
}

struct ProfileApiClient {
    base_url: String,
    access_token: String,
    http: reqwest::Client,
}

impl ProfileApiClient {
    fn new(base_url: &str, access_token: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token,
            http: reqwest::Client::new(),
        }
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let response = self
            .http
            .get(self.url(path))
            .bearer_auth(&self.access_token)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn post<T: for<'de> Deserialize<'de>>(&self, path: &str, body: Value) -> Result<T> {
        let response = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn patch<T: for<'de> Deserialize<'de>>(&self, path: &str, body: Value) -> Result<T> {
        let response = self
            .http
            .patch(self.url(path))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn put_bytes<T: for<'de> Deserialize<'de>>(&self, url: &str, body: Vec<u8>) -> Result<T> {
        let response = self
            .http
            .put(url)
            .bearer_auth(&self.access_token)
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn decode<T: for<'de> Deserialize<'de>>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();
        if status.is_success() {
            return Ok(response.json().await?);
        }
        let text = response.text().await.unwrap_or_default();
        let message = extract_error_message(&text)
            .unwrap_or_else(|| format!("cloud profile request failed ({status}): {text}"));
        if status == StatusCode::UNAUTHORIZED {
            bail!("{message}; run `opensteer-cloud login` again if your session expired");
        }
        bail!("{message}");
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

async fn profile_list(client: &ProfileApiClient) -> Result<()> {
    let profiles = list_all_profiles(client).await?;
    if profiles.is_empty() {
        println!("No browser profiles.");
        return Ok(());
    }
    for profile in profiles {
        println!("{}", format_profile_row(&profile));
    }
    Ok(())
}

async fn profile_create(client: &ProfileApiClient, name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("profiles create requires a profile name");
    }
    let profile: BrowserProfileDescriptor = client
        .post("/api/browser-profiles", json!({ "name": name }))
        .await?;
    println!("Created browser profile.");
    println!("profile: {}", profile.profile_id);
    println!("name: {}", profile.name);
    Ok(())
}

async fn profile_inspect(client: &ProfileApiClient, selector: &str) -> Result<()> {
    let profile = resolve_profile(client, selector).await?;
    println!("profile: {}", profile.profile_id);
    println!("name: {}", profile.name);
    println!("status: {}", profile.status);
    println!("cookies: {}", profile.cookie_count.unwrap_or(0));
    println!("domains: {}", profile.domain_count.unwrap_or(0));
    if let Some(revision) = profile.latest_revision {
        println!("revision: {revision}");
    }
    if let Some(session_id) = profile.active_session_id.as_deref() {
        println!("activeSession: {session_id}");
    }
    if let Some(error) = profile.last_error.as_deref() {
        println!("lastError: {error}");
    }
    if let Some(domains) = profile.cookie_domains.as_ref()
        && !domains.is_empty()
    {
        println!("cookieDomains: {}", domains.join(", "));
    }
    Ok(())
}

async fn profile_archive(client: &ProfileApiClient, selector: &str) -> Result<()> {
    let profile = resolve_profile(client, selector).await?;
    let archived: BrowserProfileDescriptor = client
        .patch(
            &format!("/api/browser-profiles/{}", profile.profile_id),
            json!({ "status": "archived" }),
        )
        .await?;
    println!("Archived browser profile.");
    println!("profile: {}", archived.profile_id);
    println!("name: {}", archived.name);
    Ok(())
}

async fn profile_sync(client: &ProfileApiClient, input: SyncCommandInput) -> Result<()> {
    let profile = resolve_profile(client, &input.profile).await?;
    let captured = snapshot::capture(CaptureInput {
        browser: input.browser,
        user_data_dir: input.user_data_dir,
        profile_directory: input.profile_directory,
        domains: input.domains,
    })?;
    let created: BrowserProfileImportCreateResponse = client
        .post(
            "/api/browser-profiles/imports",
            json!({ "profileId": profile.profile_id }),
        )
        .await?;
    if captured.payload.len() as u64 > created.max_upload_bytes {
        bail!(
            "profile snapshot is {} bytes after gzip, above the {} byte upload limit",
            captured.payload.len(),
            created.max_upload_bytes
        );
    }
    let uploaded: BrowserProfileImportDescriptor =
        client.put_bytes(&created.upload_url, captured.payload).await?;
    let imported = if uploaded.status == "ready" {
        uploaded
    } else {
        wait_for_import(client, &created.import_id).await?
    };
    let summary = imported.snapshot_summary.as_ref();
    println!("Synced browser profile cookies.");
    println!("profile: {}", imported.profile_id);
    println!("import: {}", imported.import_id);
    println!("status: {}", imported.status);
    if let Some(revision) = imported.revision {
        println!("revision: {revision}");
    }
    println!(
        "source: browser={} profile={} userDataDir={}",
        captured.brand_id,
        captured.profile_directory,
        captured.user_data_dir.display()
    );
    println!(
        "cookies: {}",
        summary
            .map(|summary| summary.cookie_count)
            .unwrap_or(captured.cookies.len() as u64)
    );
    println!(
        "domains: {}",
        summary
            .map(|summary| summary.domain_count)
            .unwrap_or(captured.domain_count as u64)
    );
    if let Some(domains) = summary.and_then(|summary| summary.cookie_domains.as_ref())
        && !domains.is_empty()
    {
        println!("cookieDomains: {}", domains.join(", "));
    }
    Ok(())
}

fn profile_local(browser: Option<&str>) -> Result<()> {
    let profiles = list_local_profiles(browser)?;
    if profiles.is_empty() {
        println!("No local Chromium profiles found.");
        return Ok(());
    }
    for profile in profiles {
        println!(
            "{}\t{}\t{}\t{}\tcookies={}",
            profile.brand_id,
            profile.profile_directory,
            profile.display_name,
            profile.user_data_dir.display(),
            if profile.cookies_path.is_some() {
                "yes"
            } else {
                "no"
            }
        );
    }
    Ok(())
}

async fn resolve_profile(
    client: &ProfileApiClient,
    selector: &str,
) -> Result<BrowserProfileDescriptor> {
    let selector = selector.trim();
    if selector.is_empty() {
        bail!("profile selector must not be empty");
    }
    if selector.starts_with("bp_") {
        return client
            .get(&format!("/api/browser-profiles/{selector}"))
            .await
            .with_context(|| format!("browser profile not found: {selector}"));
    }
    let profiles = list_all_profiles(client).await?;
    let selector_lower = selector.to_ascii_lowercase();
    let matches = profiles
        .into_iter()
        .filter(|profile| {
            profile.profile_id == selector
                || profile.profile_id.starts_with(selector)
                || profile.name == selector
                || profile.name.to_ascii_lowercase().contains(&selector_lower)
        })
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(anyhow!("browser profile not found: {selector}")),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(anyhow!("browser profile selector is ambiguous: {selector}")),
    }
}

async fn list_all_profiles(client: &ProfileApiClient) -> Result<Vec<BrowserProfileDescriptor>> {
    let mut cursor: Option<String> = None;
    let mut profiles = Vec::new();
    loop {
        let path = match cursor.as_deref() {
            Some(cursor) => format!(
                "/api/browser-profiles?limit=100&cursor={}",
                encode_query_value(cursor)
            ),
            None => "/api/browser-profiles?limit=100".to_string(),
        };
        let page: BrowserProfileListResponse = client.get(&path).await?;
        profiles.extend(page.profiles);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(profiles)
}

async fn wait_for_import(
    client: &ProfileApiClient,
    import_id: &str,
) -> Result<BrowserProfileImportDescriptor> {
    let deadline = std::time::Instant::now() + PROFILE_IMPORT_TIMEOUT;
    loop {
        let current: BrowserProfileImportDescriptor = client
            .get(&format!("/api/browser-profiles/imports/{import_id}"))
            .await?;
        match current.status.as_str() {
            "ready" => return Ok(current),
            "failed" => {
                bail!(
                    "{}",
                    current
                        .error
                        .unwrap_or_else(|| "browser profile sync failed".to_string())
                )
            }
            _ if std::time::Instant::now() >= deadline => {
                bail!("timed out waiting for browser profile import {import_id}")
            }
            _ => tokio::time::sleep(PROFILE_IMPORT_POLL_INTERVAL).await,
        }
    }
}

fn format_profile_row(profile: &BrowserProfileDescriptor) -> String {
    format!(
        "{}\t{}\t{}\tcookies={}\tdomains={}",
        profile.profile_id,
        profile.name,
        profile.status,
        profile.cookie_count.unwrap_or(0),
        profile.domain_count.unwrap_or(0)
    )
}

fn encode_query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn extract_error_message(text: &str) -> Option<String> {
    let parsed = serde_json::from_str::<Value>(text).ok()?;
    if let Some(error) = parsed.get("error") {
        if let Some(message) = error.as_str() {
            return Some(message.to_string());
        }
        if let Some(message) = error.get("message").and_then(Value::as_str) {
            return Some(message.to_string());
        }
    }
    parsed
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::encode_query_value;

    #[test]
    fn encodes_cursor_query_values() {
        assert_eq!(encode_query_value("abc-._~123"), "abc-._~123");
        assert_eq!(
            encode_query_value("next cursor+/="),
            "next%20cursor%2B%2F%3D"
        );
    }
}
