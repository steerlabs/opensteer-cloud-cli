use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use tungstenite::{Message, connect};

const CDP_START_TIMEOUT: Duration = Duration::from_secs(20);
const CDP_POLL_INTERVAL: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy)]
pub struct BrowserBrand {
    pub id_text: &'static str,
    pub name: &'static str,
    pub user_data_dir: &'static str,
    executable_path: &'static str,
}

#[derive(Debug, Clone)]
pub struct LocalBrowserProfile {
    pub brand_id: &'static str,
    pub user_data_dir: PathBuf,
    pub profile_directory: String,
    pub display_name: String,
    pub cookies_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<PortableSameSite>,
    pub session: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortableSameSite {
    Strict,
    Lax,
    None,
}

pub struct ReadBrowserCookiesInput {
    pub browser: Option<String>,
    pub user_data_dir: Option<PathBuf>,
    pub profile_directory: Option<String>,
}

pub struct ReadBrowserCookiesOutput {
    pub brand: BrowserBrand,
    pub user_data_dir: PathBuf,
    pub profile_directory: String,
    pub cookies: Vec<BrowserCookie>,
}

#[derive(Debug, Deserialize)]
struct CdpVersionResponse {
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: String,
}

#[derive(Debug, Deserialize)]
struct CdpResponse {
    id: u64,
    error: Option<CdpError>,
    result: Option<CdpCookieResult>,
}

#[derive(Debug, Deserialize)]
struct CdpError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct CdpCookieResult {
    cookies: Vec<CdpCookie>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdpCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    session: Option<bool>,
    expires: Option<f64>,
}

pub fn list_local_profiles(browser: Option<&str>) -> Result<Vec<LocalBrowserProfile>> {
    let browser_filter = browser.map(|value| value.trim().to_lowercase());
    let mut profiles = Vec::new();
    for brand in browser_brands() {
        if let Some(filter) = browser_filter.as_ref()
            && !brand.id_text.contains(filter)
            && !brand.name.to_lowercase().contains(filter)
        {
            continue;
        }
        let user_data_dir = expand_home(brand.user_data_dir);
        if !user_data_dir.exists() {
            continue;
        }
        profiles.extend(discover_profile_directories(*brand, &user_data_dir)?);
    }
    Ok(profiles)
}

pub fn read_browser_cookies(input: ReadBrowserCookiesInput) -> Result<ReadBrowserCookiesOutput> {
    let brand = match input.browser.as_deref() {
        Some(browser) => resolve_browser_brand(browser)?,
        None => detect_default_browser_brand()?,
    };
    let user_data_dir = input
        .user_data_dir
        .map(|path| expand_path(&path))
        .unwrap_or_else(|| expand_home(brand.user_data_dir));
    let profile_directory = input
        .profile_directory
        .unwrap_or_else(|| "Default".to_string());
    if !user_data_dir.join(&profile_directory).is_dir() {
        bail!(
            "browser profile not found for browser={} profile={} userDataDir={}",
            brand.id_text,
            profile_directory,
            user_data_dir.display()
        );
    }

    let cookies =
        read_cookies_through_temporary_browser(brand, &user_data_dir, &profile_directory)?;

    Ok(ReadBrowserCookiesOutput {
        brand,
        user_data_dir,
        profile_directory,
        cookies,
    })
}

pub fn filter_cookie_domains(
    cookies: Vec<BrowserCookie>,
    domains: &[String],
) -> Vec<BrowserCookie> {
    let filters = domains
        .iter()
        .map(|domain| normalize_cookie_domain(domain))
        .filter(|domain| !domain.is_empty())
        .collect::<Vec<_>>();
    if filters.is_empty() {
        return dedupe_cookies(cookies);
    }

    dedupe_cookies(
        cookies
            .into_iter()
            .filter(|cookie| {
                let domain = normalize_cookie_domain(&cookie.domain);
                filters
                    .iter()
                    .any(|filter| domain == *filter || domain.ends_with(&format!(".{filter}")))
            })
            .collect(),
    )
}

pub fn normalize_cookie_domain(domain: &str) -> String {
    domain.trim().trim_start_matches('.').to_ascii_lowercase()
}

pub fn cookie_domain_count(cookies: &[BrowserCookie]) -> usize {
    let mut domains = cookies
        .iter()
        .map(|cookie| normalize_cookie_domain(&cookie.domain))
        .filter(|domain| !domain.is_empty())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains.len()
}

fn read_cookies_through_temporary_browser(
    brand: BrowserBrand,
    source_user_data_dir: &Path,
    profile_directory: &str,
) -> Result<Vec<BrowserCookie>> {
    let executable = resolve_browser_executable(brand)?;
    let temp = tempdir().context("failed to create temporary browser profile workspace")?;
    let temp_user_data_dir = temp.path().join("user-data");
    prepare_temporary_user_data_dir(source_user_data_dir, profile_directory, &temp_user_data_dir)?;
    let port = reserve_local_port()?;
    let mut browser =
        launch_cookie_export_browser(&executable, &temp_user_data_dir, profile_directory, port)?;
    let result = get_cookies_from_cdp(port);
    terminate_child(&mut browser);
    result
}

fn prepare_temporary_user_data_dir(
    source_user_data_dir: &Path,
    profile_directory: &str,
    target_user_data_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(target_user_data_dir)
        .with_context(|| format!("failed to create {}", target_user_data_dir.display()))?;
    copy_file_if_exists(
        &source_user_data_dir.join("Local State"),
        &target_user_data_dir.join("Local State"),
    )?;
    copy_profile_directory(
        &source_user_data_dir.join(profile_directory),
        &target_user_data_dir.join(profile_directory),
    )?;
    Ok(())
}

fn copy_profile_directory(source: &Path, target: &Path) -> Result<()> {
    if !source.is_dir() {
        bail!("browser profile directory not found: {}", source.display());
    }
    fs::create_dir_all(target).with_context(|| format!("failed to create {}", target.display()))?;
    for entry in
        fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        if should_skip_profile_entry(&name_text) {
            continue;
        }
        let source_path = entry.path();
        let target_path = target.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_profile_directory(&source_path, &target_path)?;
        } else if file_type.is_file() {
            copy_file_if_exists(&source_path, &target_path)?;
        }
    }
    Ok(())
}

fn should_skip_profile_entry(name: &str) -> bool {
    matches!(
        name,
        "SingletonCookie"
            | "SingletonLock"
            | "SingletonSocket"
            | "Crashpad"
            | "Code Cache"
            | "GPUCache"
            | "GrShaderCache"
            | "ShaderCache"
            | "DawnCache"
            | "Service Worker"
            | "Cache"
    )
}

fn copy_file_if_exists(source: &Path, target: &Path) -> Result<()> {
    if !source.exists() {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::copy(source, target).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            target.display()
        )
    })?;
    Ok(())
}

fn reserve_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to reserve local CDP port")?;
    Ok(listener.local_addr()?.port())
}

fn launch_cookie_export_browser(
    executable: &Path,
    user_data_dir: &Path,
    profile_directory: &str,
    port: u16,
) -> Result<Child> {
    Command::new(executable)
        .arg(format!("--remote-debugging-port={port}"))
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg(format!("--profile-directory={profile_directory}"))
        .arg("--headless=new")
        .arg("--disable-gpu")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--no-startup-window")
        .arg("about:blank")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to launch browser at {}", executable.display()))
}

fn get_cookies_from_cdp(port: u16) -> Result<Vec<BrowserCookie>> {
    let version = wait_for_cdp_version(port)?;
    let (mut socket, _response) = connect(version.web_socket_debugger_url.as_str())
        .context("failed to connect to temporary browser CDP websocket")?;
    socket
        .send(Message::Text(
            json!({
                "id": 1,
                "method": "Storage.getCookies",
            })
            .to_string()
            .into(),
        ))
        .context("failed to request cookies from temporary browser")?;

    loop {
        let message = socket
            .read()
            .context("failed to read temporary browser CDP response")?;
        let Message::Text(text) = message else {
            continue;
        };
        let response: CdpResponse =
            serde_json::from_str(&text).context("temporary browser returned malformed CDP JSON")?;
        if response.id != 1 {
            continue;
        }
        if let Some(error) = response.error {
            bail!(
                "temporary browser failed to export cookies: {}",
                error.message
            );
        }
        let cookies = response
            .result
            .ok_or_else(|| anyhow!("temporary browser cookie response was missing result"))?
            .cookies;
        return Ok(cookies.into_iter().filter_map(map_cdp_cookie).collect());
    }
}

fn wait_for_cdp_version(port: u16) -> Result<CdpVersionResponse> {
    let deadline = Instant::now() + CDP_START_TIMEOUT;
    let url = format!("http://127.0.0.1:{port}/json/version");
    loop {
        match ureq::get(&url).call() {
            Ok(mut response) => {
                let body = response
                    .body_mut()
                    .read_to_string()
                    .context("failed to read temporary browser CDP version response")?;
                return serde_json::from_str(&body)
                    .context("temporary browser returned malformed CDP version JSON");
            }
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(CDP_POLL_INTERVAL);
            }
            Err(error) => {
                return Err(anyhow!(
                    "temporary browser did not expose CDP within {} seconds: {error}",
                    CDP_START_TIMEOUT.as_secs()
                ));
            }
        }
    }
}

fn map_cdp_cookie(cookie: CdpCookie) -> Option<BrowserCookie> {
    let name = cookie.name.trim().to_string();
    let domain = cookie.domain.trim().to_string();
    if name.is_empty() || domain.is_empty() {
        return None;
    }
    let expires_at = cookie.expires.and_then(|expires| {
        if expires > 0.0 {
            Some((expires * 1000.0) as i64)
        } else {
            None
        }
    });
    let session = cookie.session.unwrap_or(expires_at.is_none());
    Some(BrowserCookie {
        name,
        value: cookie.value,
        domain,
        path: if cookie.path.is_empty() {
            "/".to_string()
        } else {
            cookie.path
        },
        secure: cookie.secure,
        http_only: cookie.http_only,
        same_site: cookie.same_site.as_deref().and_then(map_same_site),
        session,
        expires_at: if session { None } else { expires_at },
    })
}

fn map_same_site(value: &str) -> Option<PortableSameSite> {
    match value.to_ascii_lowercase().as_str() {
        "strict" => Some(PortableSameSite::Strict),
        "lax" => Some(PortableSameSite::Lax),
        "none" => Some(PortableSameSite::None),
        _ => None,
    }
}

fn terminate_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn dedupe_cookies(cookies: Vec<BrowserCookie>) -> Vec<BrowserCookie> {
    let mut deduped: Vec<BrowserCookie> = Vec::new();
    for cookie in cookies {
        let key = (
            cookie.name.clone(),
            normalize_cookie_domain(&cookie.domain),
            cookie.path.clone(),
        );
        if let Some(index) = deduped.iter().position(|existing| {
            (
                existing.name.clone(),
                normalize_cookie_domain(&existing.domain),
                existing.path.clone(),
            ) == key
        }) {
            deduped[index] = cookie;
        } else {
            deduped.push(cookie);
        }
    }
    deduped
}

fn discover_profile_directories(
    brand: BrowserBrand,
    user_data_dir: &Path,
) -> Result<Vec<LocalBrowserProfile>> {
    let labels = read_profile_labels(user_data_dir);
    let mut candidates = labels.keys().cloned().collect::<Vec<_>>();
    if let Ok(entries) = fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "Default" || name.starts_with("Profile ") {
                candidates.push(name);
            }
        }
    }
    candidates.sort_by(|left, right| {
        let left_key = if left == "Default" { "" } else { left.as_str() };
        let right_key = if right == "Default" {
            ""
        } else {
            right.as_str()
        };
        left_key.cmp(right_key)
    });
    candidates.dedup();

    Ok(candidates
        .into_iter()
        .filter(|name| user_data_dir.join(name).exists())
        .map(|profile_directory| LocalBrowserProfile {
            brand_id: brand.id_text,
            display_name: labels
                .get(&profile_directory)
                .cloned()
                .unwrap_or_else(|| profile_directory.clone()),
            cookies_path: resolve_cookies_path(user_data_dir, &profile_directory),
            user_data_dir: user_data_dir.to_path_buf(),
            profile_directory,
        })
        .collect())
}

fn read_profile_labels(user_data_dir: &Path) -> std::collections::HashMap<String, String> {
    let mut labels = std::collections::HashMap::new();
    let Ok(raw) = fs::read_to_string(user_data_dir.join("Local State")) else {
        return labels;
    };
    let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
        return labels;
    };
    let Some(info_cache) = parsed
        .get("profile")
        .and_then(|profile| profile.get("info_cache"))
        .and_then(Value::as_object)
    else {
        return labels;
    };
    for (profile_directory, info) in info_cache {
        if let Some(name) = info.get("name").and_then(Value::as_str)
            && !name.trim().is_empty()
        {
            labels.insert(profile_directory.clone(), name.trim().to_string());
        }
    }
    labels
}

fn resolve_browser_executable(brand: BrowserBrand) -> Result<PathBuf> {
    let path = PathBuf::from(brand.executable_path);
    if path.exists() {
        return Ok(path);
    }
    bail!(
        "{} executable was not found at {}; install the browser or pass a supported --browser",
        brand.name,
        path.display()
    )
}

fn detect_default_browser_brand() -> Result<BrowserBrand> {
    browser_brands()
        .iter()
        .copied()
        .find(|brand| expand_home(brand.user_data_dir).exists())
        .ok_or_else(|| {
            anyhow!("no supported Chromium browser profile was found; pass --browser and --user-data-dir")
        })
}

fn resolve_browser_brand(value: &str) -> Result<BrowserBrand> {
    let normalized = value.trim().to_ascii_lowercase();
    browser_brands()
        .iter()
        .copied()
        .find(|brand| brand.id_text == normalized || brand.name.to_ascii_lowercase() == normalized)
        .ok_or_else(|| {
            anyhow!(
                "unknown browser {}; expected one of {}",
                value,
                browser_brands()
                    .iter()
                    .map(|brand| brand.id_text)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn resolve_cookies_path(user_data_dir: &Path, profile_directory: &str) -> Option<PathBuf> {
    [
        user_data_dir
            .join(profile_directory)
            .join("Network")
            .join("Cookies"),
        user_data_dir.join(profile_directory).join("Cookies"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn browser_brands() -> &'static [BrowserBrand] {
    if cfg!(target_os = "macos") {
        &[
            BrowserBrand {
                id_text: "chrome",
                name: "Google Chrome",
                user_data_dir: "~/Library/Application Support/Google/Chrome",
                executable_path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            },
            BrowserBrand {
                id_text: "chrome-canary",
                name: "Google Chrome Canary",
                user_data_dir: "~/Library/Application Support/Google/Chrome Canary",
                executable_path: "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
            },
            BrowserBrand {
                id_text: "edge",
                name: "Microsoft Edge",
                user_data_dir: "~/Library/Application Support/Microsoft Edge",
                executable_path: "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            },
            BrowserBrand {
                id_text: "brave",
                name: "Brave Browser",
                user_data_dir: "~/Library/Application Support/BraveSoftware/Brave-Browser",
                executable_path: "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            },
            BrowserBrand {
                id_text: "vivaldi",
                name: "Vivaldi",
                user_data_dir: "~/Library/Application Support/Vivaldi",
                executable_path: "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
            },
            BrowserBrand {
                id_text: "chromium",
                name: "Chromium",
                user_data_dir: "~/Library/Application Support/Chromium",
                executable_path: "/Applications/Chromium.app/Contents/MacOS/Chromium",
            },
            BrowserBrand {
                id_text: "helium",
                name: "Helium",
                user_data_dir: "~/Library/Application Support/net.imput.helium",
                executable_path: "/Applications/Helium.app/Contents/MacOS/Helium",
            },
        ]
    } else if cfg!(target_os = "windows") {
        &[
            BrowserBrand {
                id_text: "chrome",
                name: "Google Chrome",
                user_data_dir: "~/AppData/Local/Google/Chrome/User Data",
                executable_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            },
            BrowserBrand {
                id_text: "edge",
                name: "Microsoft Edge",
                user_data_dir: "~/AppData/Local/Microsoft/Edge/User Data",
                executable_path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            },
            BrowserBrand {
                id_text: "brave",
                name: "Brave Browser",
                user_data_dir: "~/AppData/Local/BraveSoftware/Brave-Browser/User Data",
                executable_path: "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            },
            BrowserBrand {
                id_text: "chromium",
                name: "Chromium",
                user_data_dir: "~/AppData/Local/Chromium/User Data",
                executable_path: "C:\\Program Files\\Chromium\\Application\\chromium.exe",
            },
        ]
    } else {
        &[
            BrowserBrand {
                id_text: "chrome",
                name: "Google Chrome",
                user_data_dir: "~/.config/google-chrome",
                executable_path: "/usr/bin/google-chrome",
            },
            BrowserBrand {
                id_text: "edge",
                name: "Microsoft Edge",
                user_data_dir: "~/.config/microsoft-edge",
                executable_path: "/usr/bin/microsoft-edge",
            },
            BrowserBrand {
                id_text: "brave",
                name: "Brave Browser",
                user_data_dir: "~/.config/BraveSoftware/Brave-Browser",
                executable_path: "/usr/bin/brave-browser",
            },
            BrowserBrand {
                id_text: "vivaldi",
                name: "Vivaldi",
                user_data_dir: "~/.config/vivaldi",
                executable_path: "/usr/bin/vivaldi",
            },
            BrowserBrand {
                id_text: "chromium",
                name: "Chromium",
                user_data_dir: "~/.config/chromium",
                executable_path: "/usr/bin/chromium",
            },
        ]
    }
}

fn expand_home(path: &str) -> PathBuf {
    if path == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from(path));
    }
    if let Some(stripped) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(stripped);
    }
    PathBuf::from(path)
}

fn expand_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        expand_home(&text)
    } else {
        path.to_path_buf()
    }
}
