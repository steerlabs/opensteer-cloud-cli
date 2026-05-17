use crate::snapshot::{CaptureInput, capture as capture_snapshot};
use reqwest::StatusCode;
use serde::Deserialize;
use std::path::PathBuf;

/// Typed CLI exit codes for `opensteer-cloud claim`. The numeric values are
/// stable so LLM-driven callers (Claude Code, Codex) can branch on them.
/// `InvalidArgs` and `AmbiguousLocalProfile` are reserved for future
/// detection paths; the SKILL docs list the full mapping.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum CliExit {
    Success = 0,
    InvalidArgs = 64,
    AmbiguousLocalProfile = 65,
    RequestNotFound = 66,
    LocalBrowserMissing = 67,
    LocalCaptureFailed = 68,
    UploadFailed = 69,
    CliTooOld = 70,
    ServerError = 71,
}

pub struct ClaimInput {
    pub request_id: String,
    pub browser: Option<String>,
    pub user_data_dir: Option<PathBuf>,
    pub profile_directory: Option<String>,
    pub domains: Vec<String>,
}

#[derive(Deserialize)]
struct ClaimResponse {
    status: String,
    #[serde(rename = "profileName")]
    profile_name: Option<String>,
    #[serde(rename = "cookieCount")]
    cookie_count: Option<u64>,
    #[serde(rename = "domainCount")]
    domain_count: Option<u64>,
    #[serde(rename = "minCliVersion")]
    min_cli_version: Option<String>,
    error: Option<String>,
    message: Option<String>,
}

const CURRENT_CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run_claim(input: ClaimInput, base_url: &str, access_token: String) -> CliExit {
    let captured = match capture_snapshot(CaptureInput {
        browser: input.browser.clone(),
        user_data_dir: input.user_data_dir.clone(),
        profile_directory: input.profile_directory.clone(),
        domains: input.domains.clone(),
    }) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let message = format!("{error}");
            if message.contains("not found") || message.contains("executable was not found") {
                eprintln!(
                    "error=local_browser_missing hint=\"install the browser or pass --browser/--user-data-dir\""
                );
                return CliExit::LocalBrowserMissing;
            }
            eprintln!("error=local_capture_failed message=\"{message}\"");
            return CliExit::LocalCaptureFailed;
        }
    };

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/browser-profile-requests/{}/import",
        base_url.trim_end_matches('/'),
        urlencoding::encode(&input.request_id),
    );

    let response = match client
        .post(&url)
        .bearer_auth(&access_token)
        .header("content-type", "application/octet-stream")
        .body(captured.payload)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            eprintln!("error=upload_failed message=\"{error}\"");
            return CliExit::UploadFailed;
        }
    };

    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();
    let parsed: ClaimResponse = match serde_json::from_str(&body_text) {
        Ok(parsed) => parsed,
        Err(_) => {
            eprintln!(
                "error=server_error status={} body=\"{}\"",
                status.as_u16(),
                body_text.replace('"', "'")
            );
            return CliExit::ServerError;
        }
    };

    if let Some(min_version) = parsed.min_cli_version.as_deref()
        && compare_versions(CURRENT_CLI_VERSION, min_version) < 0
    {
        eprintln!(
            "error=cli_too_old current={CURRENT_CLI_VERSION} required={min_version} hint=\"reinstall via curl -fsSL https://opensteer.com/cloud-cli/install.sh | sh\""
        );
        return CliExit::CliTooOld;
    }

    if status == StatusCode::NOT_FOUND || parsed.error.as_deref() == Some("request_not_found") {
        eprintln!(
            "error=request_not_found request_id={} hint=\"open the cloud workspace and click Import again\"",
            input.request_id
        );
        return CliExit::RequestNotFound;
    }
    if !status.is_success() {
        eprintln!(
            "error=server_error status={} message=\"{}\"",
            status.as_u16(),
            parsed
                .error
                .or(parsed.message)
                .unwrap_or_else(|| body_text.replace('"', "'"))
        );
        return CliExit::ServerError;
    }

    match parsed.status.as_str() {
        "resolved" => {
            println!(
                "Imported \"{}\" — {} cookies, {} domains.",
                parsed.profile_name.unwrap_or_default(),
                parsed.cookie_count.unwrap_or(0),
                parsed.domain_count.unwrap_or(0)
            );
            println!("Resolved your cloud workspace's pending profile request.");
            CliExit::Success
        }
        "already_completed" => {
            println!(
                "Cloud workspace already resolved this session — your import is redundant but harmless."
            );
            CliExit::Success
        }
        "request_canceled" => {
            println!(
                "The cloud workspace canceled this request before your CLI finished — your snapshot was discarded."
            );
            CliExit::Success
        }
        other => {
            eprintln!("error=server_error message=\"unexpected status: {other}\"");
            CliExit::ServerError
        }
    }
}

fn compare_versions(left: &str, right: &str) -> i32 {
    let left_parts: Vec<u32> = left.split('.').filter_map(|s| s.parse().ok()).collect();
    let right_parts: Vec<u32> = right.split('.').filter_map(|s| s.parse().ok()).collect();
    for i in 0..left_parts.len().max(right_parts.len()) {
        let l = left_parts.get(i).copied().unwrap_or(0);
        let r = right_parts.get(i).copied().unwrap_or(0);
        if l < r {
            return -1;
        }
        if l > r {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_orders_correctly() {
        assert_eq!(compare_versions("0.1.0", "0.2.0"), -1);
        assert_eq!(compare_versions("0.2.0", "0.2.0"), 0);
        assert_eq!(compare_versions("0.2.1", "0.2.0"), 1);
        assert_eq!(compare_versions("1.0.0", "0.99.99"), 1);
    }
}
