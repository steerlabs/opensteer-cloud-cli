mod browser_profiles;
mod local_browser;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use clap::{Parser, Subcommand};
use fs4::FileExt;
use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::sync::Mutex;

const DEFAULT_BASE_URL: &str = "http://localhost:3001";
const TEMPLATE_DESCRIPTOR_PATH: &str = ".opensteer/template.json";
const ACCESS_TOKEN_LEEWAY_SECS: u64 = 30;

#[derive(Parser)]
#[command(name = "opensteer-cloud")]
#[command(about = "OpenSteer Cloud control-plane CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Login,
    Logout,
    Whoami,
    Attach {
        agent: String,
    },
    Browser {
        #[command(subcommand)]
        command: BrowserCommands,
    },
    Profiles {
        #[command(subcommand)]
        command: browser_profiles::ProfileCommands,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    Templates {
        #[command(subcommand)]
        command: TemplateCommands,
    },
}

#[derive(Subcommand)]
enum AgentCommands {
    Create { prompt: Vec<String> },
    List,
    Open { agent: String },
    Rm { agent: String },
}

#[derive(Subcommand)]
enum BrowserCommands {
    Open { agent: String, url: String },
    Save { agent: String },
    Close { agent: String },
    Focus { agent: String },
}

#[derive(Subcommand)]
enum TemplateCommands {
    Search { query: Vec<String> },
    Inspect { id: String },
    Apply { id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    if is_opensteer_run_invocation() {
        let exit_code = opensteer_run().await?;
        std::process::exit(exit_code);
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Login => login().await,
        Commands::Logout => logout().await,
        Commands::Whoami => whoami().await,
        Commands::Attach { agent } => attach(&agent).await,
        Commands::Browser { command } => match command {
            BrowserCommands::Open { agent, url } => browser_open(&agent, &url).await,
            BrowserCommands::Save { agent } => browser_save(&agent).await,
            BrowserCommands::Close { agent } => browser_close(&agent).await,
            BrowserCommands::Focus { agent } => agent_open(&agent).await,
        },
        Commands::Profiles { command } => profiles(command).await,
        Commands::Agent { command } => match command {
            AgentCommands::Create { prompt } => agent_create(&prompt.join(" ")).await,
            AgentCommands::List => agent_list().await,
            AgentCommands::Open { agent } => agent_open(&agent).await,
            AgentCommands::Rm { agent } => agent_rm(&agent).await,
        },
        Commands::Templates { command } => match command {
            TemplateCommands::Search { query } => template_search(&query.join(" ")),
            TemplateCommands::Inspect { id } => template_inspect(&id),
            TemplateCommands::Apply { id } => template_apply(&id),
        },
    }
}

// ----- Command handlers ---------------------------------------------------

async fn profiles(command: browser_profiles::ProfileCommands) -> Result<()> {
    if !browser_profiles::requires_cloud_auth(&command) {
        return browser_profiles::handle(command, "", String::new()).await;
    }
    let auth = AuthStore::open()?;
    let access_token = auth.bearer_token().await?;
    browser_profiles::handle(command, auth.base_url(), access_token).await
}

async fn login() -> Result<()> {
    let auth = AuthStore::open()?;
    let base_url = auth.base_url().to_string();
    let client = reqwest::Client::new();
    let start: DeviceStartResponse = client
        .post(api_url(&base_url, "/api/cli-auth/device/start")?)
        .json(&json!({ "scope": "cloud:browser cloud:agents" }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!("Open this URL to authorize OpenSteer Cloud:");
    println!("{}", start.verification_uri_complete);
    println!("Code: {}", start.user_code);
    let _ = open::that(&start.verification_uri_complete);

    let deadline = now_secs() + start.expires_in;
    let mut interval = start.interval.max(1);
    loop {
        if now_secs() >= deadline {
            return Err(anyhow!("device login expired; run login again"));
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let response = client
            .post(api_url(&base_url, "/api/cli-auth/device/token")?)
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": start.device_code
            }))
            .send()
            .await?;

        if response.status().is_success() {
            let token: TokenResponse = response.json().await?;
            auth.save_initial(AuthRecord {
                base_url,
                access_token: token.access_token,
                access_expires_at: now_secs() + token.expires_in,
                refresh_token: token.refresh_token,
            })
            .await?;
            println!("Logged in.");
            return Ok(());
        }

        let status = response.status();
        let error: OAuthError = response.json().await.unwrap_or(OAuthError {
            error: "server_error".to_string(),
            error_description: None,
            interval: None,
        });
        if error.error == "authorization_pending" {
            continue;
        }
        if error.error == "slow_down" {
            interval = error.interval.unwrap_or(interval + 1).max(interval + 1);
            continue;
        }
        return Err(anyhow!(
            "{}",
            error
                .error_description
                .unwrap_or_else(|| format!("login failed with {status}"))
        ));
    }
}

async fn logout() -> Result<()> {
    let auth = AuthStore::open()?;
    if let Some(refresh_token) = auth.current_refresh_token().await? {
        let client = reqwest::Client::new();
        let _ = client
            .post(api_url(auth.base_url(), "/api/cli-auth/revoke")?)
            .json(&json!({ "refresh_token": refresh_token }))
            .send()
            .await;
    }
    auth.clear().await?;
    let connection = ConnectionStore::open()?;
    connection.clear().await?;
    println!("Logged out.");
    Ok(())
}

async fn whoami() -> Result<()> {
    let auth = AuthStore::open()?;
    let _token = auth.bearer_token().await?;
    let agents = list_agents(&auth).await?;
    println!("Logged in to {}", auth.base_url());
    println!("Agents visible: {}", agents.len());
    Ok(())
}

async fn agent_create(prompt: &str) -> Result<()> {
    let name = prompt.trim();
    if name.is_empty() {
        return Err(anyhow!("agent create requires a prompt/name"));
    }
    let auth = AuthStore::open()?;
    let response: AgentCreateResponse = api_post(
        &auth,
        "/api/agents",
        &json!({
            "name": name
        }),
    )
    .await?;
    println!("Created agent: {}", response.cloud_agent.name);
    println!("id: {}", response.cloud_agent.id);
    println!(
        "open: {}/agents/{}",
        auth.base_url(),
        response.cloud_agent.id
    );
    Ok(())
}

async fn agent_list() -> Result<()> {
    let auth = AuthStore::open()?;
    let agents = list_agents(&auth).await?;
    for agent in agents {
        println!("{}\t{}", agent.id, agent.name);
    }
    Ok(())
}

async fn agent_open(agent: &str) -> Result<()> {
    let auth = AuthStore::open()?;
    let agent = resolve_agent(&auth, agent).await?;
    let url = format!("{}/agents/{}", auth.base_url(), agent.id);
    open::that(&url)?;
    println!("{url}");
    Ok(())
}

async fn agent_rm(agent: &str) -> Result<()> {
    let auth = AuthStore::open()?;
    let agent = resolve_agent(&auth, agent).await?;
    api_delete(&auth, &format!("/api/agents/{}", agent.id)).await?;
    println!("Removed {}", agent.id);
    Ok(())
}

async fn browser_open(agent: &str, url: &str) -> Result<()> {
    let auth = AuthStore::open()?;
    let agent = resolve_agent(&auth, agent).await?;
    let response: Value = api_post(
        &auth,
        &format!("/api/agents/{}/browser/open", agent.id),
        &json!({
            "url": url,
            "reveal": true,
        }),
    )
    .await?;
    let ui_url = format!("{}/agents/{}", auth.base_url(), agent.id);
    let _ = open::that(&ui_url);
    println!("Opened browser for {}.", agent.name);
    if let Some(session_id) = response.get("sessionId").and_then(Value::as_str) {
        println!("session: {session_id}");
    }
    println!("agent UI: {ui_url}");
    Ok(())
}

async fn browser_save(agent: &str) -> Result<()> {
    let auth = AuthStore::open()?;
    let agent = resolve_agent(&auth, agent).await?;
    let response: Value = api_post(
        &auth,
        &format!("/api/agents/{}/browser/save", agent.id),
        &json!({}),
    )
    .await?;
    println!("Saved browser profile for {}.", agent.name);
    if let Some(session_id) = response.get("sessionId").and_then(Value::as_str) {
        println!("session: {session_id}");
    }
    Ok(())
}

async fn browser_close(agent: &str) -> Result<()> {
    let auth = AuthStore::open()?;
    let agent = resolve_agent(&auth, agent).await?;
    api_delete(&auth, &format!("/api/agents/{}/browser/session", agent.id)).await?;
    println!("Closed browser for {}.", agent.name);
    Ok(())
}

async fn attach(agent_selector: &str) -> Result<()> {
    let auth = AuthStore::open()?;
    let connection_store = ConnectionStore::open()?;
    let agent = resolve_agent(&auth, agent_selector).await?;
    let response: WorkspaceBootstrapResponse =
        api_get(&auth, &format!("/api/agents/{}/workspace", agent.id)).await?;
    connection_store
        .set(ActiveConnection {
            cloud_agent_id: agent.id.clone(),
            cloud_agent_name: agent.name.clone(),
            workspace_id: response
                .workspace
                .as_ref()
                .map(|workspace| workspace.id.clone()),
            sandbox_id: response
                .workspace
                .as_ref()
                .and_then(|workspace| workspace.sandbox_id.clone()),
            attached_at: now_secs(),
        })
        .await?;
    let agent_url = format!("{}/agents/{}", auth.base_url(), agent.id);
    let _ = open::that(&agent_url);
    println!("Attached to {}.", agent.name);
    println!("Agent UI: {agent_url}");
    println!("Sandbox workspace is now the source of truth.");
    println!(
        "Use opensteer-run for every sandbox command, file read, file write, search, and patch."
    );
    println!("Do not cd into a local mirror; no local sandbox workspace is required.");
    println!("Examples:");
    println!("  opensteer-run ls .");
    println!("  opensteer-run read skills/SKILL.md");
    println!("  opensteer-run \"python actions/job.py\"");
    println!("  opensteer-run patch < change.diff");
    Ok(())
}

async fn opensteer_run() -> Result<i32> {
    let connection_store = ConnectionStore::open()?;
    let connection = connection_store
        .get()
        .await?
        .ok_or_else(|| anyhow!("no active sandbox; run opensteer-cloud attach <agent>"))?;
    let auth = AuthStore::open()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_opensteer_run_usage();
        return Ok(2);
    }

    match args[0].as_str() {
        "exec" => {
            let command = args[1..].join(" ");
            run_exec_command(&auth, &connection, &command).await
        }
        "read" => {
            let path = require_run_arg(&args, 1, "read <path>")?;
            run_read_file(&auth, &connection, path).await
        }
        "write" => {
            let path = require_run_arg(&args, 1, "write <path>")?;
            run_write_file(&auth, &connection, path, false).await
        }
        "append" => {
            let path = require_run_arg(&args, 1, "append <path>")?;
            run_write_file(&auth, &connection, path, true).await
        }
        "ls" => {
            let path = args.get(1).map(String::as_str).unwrap_or(".");
            run_list_files(&auth, &connection, path).await
        }
        "stat" => {
            let path = require_run_arg(&args, 1, "stat <path>")?;
            run_stat_path(&auth, &connection, path).await
        }
        "mkdir" => {
            let path = require_run_arg(&args, 1, "mkdir <path>")?;
            run_mkdir(&auth, &connection, path).await
        }
        "rm" => {
            let recursive = args.iter().any(|arg| arg == "-r" || arg == "--recursive");
            let path = args
                .iter()
                .skip(1)
                .find(|arg| arg.as_str() != "-r" && arg.as_str() != "--recursive")
                .map(String::as_str)
                .ok_or_else(|| anyhow!("usage: opensteer-run rm [--recursive] <path>"))?;
            run_rm(&auth, &connection, path, recursive).await
        }
        "patch" => run_patch(&auth, &connection).await,
        "rg" => {
            let pattern = require_run_arg(&args, 1, "rg <pattern> [path...]")?;
            let paths = if args.len() > 2 { &args[2..] } else { &[] };
            let command = build_rg_command(pattern, paths);
            run_exec_command(&auth, &connection, &command).await
        }
        "help" | "--help" | "-h" => {
            print_opensteer_run_usage();
            Ok(0)
        }
        _ => run_exec_command(&auth, &connection, &args.join(" ")).await,
    }
}

async fn run_exec_command(
    auth: &AuthStore,
    connection: &ActiveConnection,
    command: &str,
) -> Result<i32> {
    if command.trim().is_empty() {
        return Err(anyhow!("usage: opensteer-run exec \"command\""));
    }
    let stdin_base64 = read_piped_stdin_base64()?;
    let mut body = json!({
        "command": command,
        "injectProviderApiKeys": false,
    });
    if let Some(stdin_base64) = stdin_base64 {
        body["stdinBase64"] = Value::String(stdin_base64);
    }

    let response = api_post_response(
        auth,
        &format!("/api/agents/{}/run/exec", connection.cloud_agent_id),
        &body,
    )
    .await?;
    stream_run_events(response).await
}

async fn run_read_file(auth: &AuthStore, connection: &ActiveConnection, path: &str) -> Result<i32> {
    let file: RunFileReadResponse = api_post(
        auth,
        &format!("/api/agents/{}/run/files/read", connection.cloud_agent_id),
        &json!({ "path": path }),
    )
    .await?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(file.content_base64.as_bytes())
        .context("sandbox returned invalid base64 file content")?;
    std::io::stdout().write_all(&bytes)?;
    Ok(0)
}

async fn run_write_file(
    auth: &AuthStore,
    connection: &ActiveConnection,
    path: &str,
    append: bool,
) -> Result<i32> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    let content_base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let _: RunMutationResponse = api_post(
        auth,
        &format!("/api/agents/{}/run/files/write", connection.cloud_agent_id),
        &json!({
            "path": path,
            "contentBase64": content_base64,
            "append": append,
        }),
    )
    .await?;
    Ok(0)
}

async fn run_list_files(
    auth: &AuthStore,
    connection: &ActiveConnection,
    path: &str,
) -> Result<i32> {
    let list: RunFileListResponse = api_post(
        auth,
        &format!("/api/agents/{}/run/files/list", connection.cloud_agent_id),
        &json!({ "path": path }),
    )
    .await?;
    for entry in list.entries {
        let suffix = if entry.entry_type == "directory" {
            "/"
        } else {
            ""
        };
        println!("{}{}", entry.path, suffix);
    }
    Ok(0)
}

async fn run_stat_path(auth: &AuthStore, connection: &ActiveConnection, path: &str) -> Result<i32> {
    let stat: Value = api_post(
        auth,
        &format!("/api/agents/{}/run/files/stat", connection.cloud_agent_id),
        &json!({ "path": path }),
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&stat)?);
    Ok(0)
}

async fn run_mkdir(auth: &AuthStore, connection: &ActiveConnection, path: &str) -> Result<i32> {
    let _: RunMutationResponse = api_post(
        auth,
        &format!("/api/agents/{}/run/files/mkdir", connection.cloud_agent_id),
        &json!({ "path": path }),
    )
    .await?;
    Ok(0)
}

async fn run_rm(
    auth: &AuthStore,
    connection: &ActiveConnection,
    path: &str,
    recursive: bool,
) -> Result<i32> {
    let _: RunMutationResponse = api_post(
        auth,
        &format!("/api/agents/{}/run/files/rm", connection.cloud_agent_id),
        &json!({ "path": path, "recursive": recursive }),
    )
    .await?;
    Ok(0)
}

async fn run_patch(auth: &AuthStore, connection: &ActiveConnection) -> Result<i32> {
    let mut patch = String::new();
    std::io::stdin().read_to_string(&mut patch)?;
    if patch.trim().is_empty() {
        return Err(anyhow!(
            "opensteer-run patch expects a unified diff on stdin"
        ));
    }
    let result: RunPatchResponse = api_post(
        auth,
        &format!("/api/agents/{}/run/files/patch", connection.cloud_agent_id),
        &json!({ "patch": patch }),
    )
    .await?;
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    Ok(result.exit_code.unwrap_or(if result.ok { 0 } else { 1 }))
}

fn read_piped_stdin_base64() -> Result<Option<String>> {
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        base64::engine::general_purpose::STANDARD.encode(bytes),
    ))
}

async fn stream_run_events(mut response: Response) -> Result<i32> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut exit_code = None;
    while let Some(chunk) = response.chunk().await? {
        buffer.extend_from_slice(&chunk);
        while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            let line = buffer.drain(..=newline).collect::<Vec<_>>();
            handle_run_event_bytes(&line[..line.len().saturating_sub(1)], &mut exit_code)?;
        }
    }
    if !buffer.iter().all(u8::is_ascii_whitespace) {
        handle_run_event_bytes(&buffer, &mut exit_code)?;
    }
    Ok(exit_code.unwrap_or(1))
}

fn handle_run_event_bytes(line: &[u8], exit_code: &mut Option<i32>) -> Result<()> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let line = std::str::from_utf8(line).context("sandbox run stream emitted invalid UTF-8")?;
    handle_run_event_line(line, exit_code)
}

fn handle_run_event_line(line: &str, exit_code: &mut Option<i32>) -> Result<()> {
    match serde_json::from_str::<RunStreamEvent>(line)? {
        RunStreamEvent::Stdout { chunk } => {
            print!("{chunk}");
            std::io::stdout().flush()?;
        }
        RunStreamEvent::Stderr { chunk } => {
            eprint!("{chunk}");
            std::io::stderr().flush()?;
        }
        RunStreamEvent::Exit {
            exit_code: code, ..
        } => {
            *exit_code = Some(code.unwrap_or(1));
        }
        RunStreamEvent::Error { message } => {
            eprintln!("opensteer-run: {message}");
            *exit_code = Some(1);
        }
    }
    Ok(())
}

fn build_rg_command(pattern: &str, paths: &[String]) -> String {
    let mut parts = vec![
        "rg".to_string(),
        "--line-number".to_string(),
        "--no-heading".to_string(),
        shell_quote(pattern),
    ];
    if paths.is_empty() {
        parts.push(".".to_string());
    } else {
        parts.extend(paths.iter().map(|path| shell_quote(path)));
    }
    parts.join(" ")
}

fn require_run_arg<'a>(args: &'a [String], index: usize, usage: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("usage: opensteer-run {usage}"))
}

fn print_opensteer_run_usage() {
    eprintln!(
        "usage:
  opensteer-run exec \"<command>\"
  opensteer-run \"<command>\"
  opensteer-run read <path>
  opensteer-run write <path> < local-file
  opensteer-run append <path> < input
  opensteer-run patch < change.diff
  opensteer-run ls [path]
  opensteer-run stat <path>
  opensteer-run mkdir <path>
  opensteer-run rm [--recursive] <path>
  opensteer-run rg <pattern> [path...]"
    );
}

async fn list_agents(auth: &AuthStore) -> Result<Vec<CloudAgent>> {
    let response: AgentListResponse = api_get(auth, "/api/agents").await?;
    Ok(response.cloud_agents)
}

async fn resolve_agent(auth: &AuthStore, selector: &str) -> Result<CloudAgent> {
    let agents = list_agents(auth).await?;
    let matches: Vec<_> = agents
        .into_iter()
        .filter(|agent| {
            agent.id == selector
                || agent.name == selector
                || agent.id.starts_with(selector)
                || agent.name.to_lowercase().contains(&selector.to_lowercase())
        })
        .collect();
    match matches.len() {
        0 => Err(anyhow!("agent not found: {selector}")),
        1 => Ok(matches[0].clone()),
        _ => Err(anyhow!("agent selector is ambiguous: {selector}")),
    }
}

// ----- API helpers ----------------------------------------------------------

async fn api_get<T: for<'de> Deserialize<'de>>(auth: &AuthStore, path: &str) -> Result<T> {
    let token = auth.bearer_token().await?;
    let response = reqwest::Client::new()
        .get(api_url(auth.base_url(), path)?)
        .bearer_auth(token)
        .send()
        .await?;
    decode_response(response).await
}

async fn api_post<T: for<'de> Deserialize<'de>>(
    auth: &AuthStore,
    path: &str,
    body: &Value,
) -> Result<T> {
    let token = auth.bearer_token().await?;
    let response = reqwest::Client::new()
        .post(api_url(auth.base_url(), path)?)
        .bearer_auth(token)
        .json(body)
        .send()
        .await?;
    decode_response(response).await
}

async fn api_post_response(auth: &AuthStore, path: &str, body: &Value) -> Result<Response> {
    let token = auth.bearer_token().await?;
    let response = reqwest::Client::new()
        .post(api_url(auth.base_url(), path)?)
        .bearer_auth(token)
        .json(body)
        .send()
        .await?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let text = response.text().await.unwrap_or_default();
    Err(anyhow!("request failed ({status}): {text}"))
}

async fn api_delete(auth: &AuthStore, path: &str) -> Result<()> {
    let token = auth.bearer_token().await?;
    let response = reqwest::Client::new()
        .delete(api_url(auth.base_url(), path)?)
        .bearer_auth(token)
        .send()
        .await?;
    let _: Value = decode_response(response).await?;
    Ok(())
}

async fn decode_response<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T> {
    let status = response.status();
    if status.is_success() {
        return Ok(response.json().await?);
    }
    let text = response.text().await.unwrap_or_default();
    Err(anyhow!("request failed ({status}): {text}"))
}

// ----- AuthStore ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthRecord {
    base_url: String,
    access_token: String,
    access_expires_at: u64,
    refresh_token: String,
}

#[derive(Debug, Error)]
enum AuthError {
    #[error("not logged in; run `opensteer-cloud login`")]
    NotLoggedIn,
    #[error("Your session has expired. Run `opensteer-cloud login` to sign in again.")]
    RefreshExpired,
    #[error("opensteer-cloud config file is malformed: {0}")]
    Malformed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("auth server error ({status}): {body}")]
    Server { status: StatusCode, body: String },
}

struct AuthStore {
    auth_path: PathBuf,
    lock_path: PathBuf,
    base_url: String,
    in_process: Mutex<()>,
}

impl AuthStore {
    fn open() -> Result<Self> {
        let dir = config_dir()?;
        let auth_path = dir.join("auth.json");
        let lock_path = dir.join("auth.lock");
        let base_url = resolve_base_url(read_persisted_base_url(&auth_path));
        Ok(Self {
            auth_path,
            lock_path,
            base_url,
            in_process: Mutex::new(()),
        })
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn bearer_token(&self) -> Result<String, AuthError> {
        let _process_guard = self.in_process.lock().await;
        let _file_lock = FileLock::acquire_exclusive(&self.lock_path)?;

        let mut record = read_json::<AuthRecord>(&self.auth_path)?.ok_or(AuthError::NotLoggedIn)?;

        if record.access_expires_at > now_secs() + ACCESS_TOKEN_LEEWAY_SECS {
            return Ok(record.access_token);
        }

        record = match refresh_tokens(&self.base_url, &record).await {
            Ok(next) => next,
            Err(AuthError::RefreshExpired) => {
                let _ = fs::remove_file(&self.auth_path);
                return Err(AuthError::RefreshExpired);
            }
            Err(other) => return Err(other),
        };

        atomic_write_json(&self.auth_path, &record)?;
        Ok(record.access_token)
    }

    async fn save_initial(&self, record: AuthRecord) -> Result<(), AuthError> {
        let _process_guard = self.in_process.lock().await;
        let _file_lock = FileLock::acquire_exclusive(&self.lock_path)?;
        atomic_write_json(&self.auth_path, &record)?;
        Ok(())
    }

    async fn current_refresh_token(&self) -> Result<Option<String>, AuthError> {
        let _process_guard = self.in_process.lock().await;
        let _file_lock = FileLock::acquire_exclusive(&self.lock_path)?;
        Ok(read_json::<AuthRecord>(&self.auth_path)?.map(|r| r.refresh_token))
    }

    async fn clear(&self) -> Result<(), AuthError> {
        let _process_guard = self.in_process.lock().await;
        let _file_lock = FileLock::acquire_exclusive(&self.lock_path)?;
        if let Err(error) = fs::remove_file(&self.auth_path)
            && error.kind() != ErrorKind::NotFound
        {
            return Err(error.into());
        }
        Ok(())
    }
}

async fn refresh_tokens(base_url: &str, current: &AuthRecord) -> Result<AuthRecord, AuthError> {
    let response = reqwest::Client::new()
        .post(
            api_url(base_url, "/api/cli-auth/token").map_err(|e| AuthError::Server {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: e.to_string(),
            })?,
        )
        .json(&json!({
            "grant_type": "refresh_token",
            "refresh_token": current.refresh_token
        }))
        .send()
        .await?;

    let status = response.status();
    if status.is_success() {
        let token: TokenResponse = response.json().await?;
        return Ok(AuthRecord {
            base_url: current.base_url.clone(),
            access_token: token.access_token,
            access_expires_at: now_secs() + token.expires_in,
            refresh_token: token.refresh_token,
        });
    }

    let body_text = response.text().await.unwrap_or_default();
    if let Ok(error) = serde_json::from_str::<OAuthError>(&body_text)
        && error.error == "invalid_grant"
    {
        return Err(AuthError::RefreshExpired);
    }
    Err(AuthError::Server {
        status,
        body: body_text,
    })
}

// ----- ConnectionStore ------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveConnection {
    #[serde(rename = "cloudAgentId")]
    cloud_agent_id: String,
    #[serde(rename = "cloudAgentName")]
    cloud_agent_name: String,
    #[serde(rename = "workspaceId")]
    workspace_id: Option<String>,
    #[serde(rename = "sandboxId")]
    sandbox_id: Option<String>,
    #[serde(rename = "attachedAt")]
    attached_at: u64,
}

struct ConnectionStore {
    connection_path: PathBuf,
    lock_path: PathBuf,
    in_process: Mutex<()>,
}

impl ConnectionStore {
    fn open() -> Result<Self> {
        let dir = config_dir()?;
        Ok(Self {
            connection_path: dir.join("connection.json"),
            lock_path: dir.join("connection.lock"),
            in_process: Mutex::new(()),
        })
    }

    async fn get(&self) -> Result<Option<ActiveConnection>> {
        let _process_guard = self.in_process.lock().await;
        let _file_lock = FileLock::acquire_exclusive(&self.lock_path)?;
        Ok(read_json::<ActiveConnection>(&self.connection_path)?)
    }

    async fn set(&self, connection: ActiveConnection) -> Result<()> {
        let _process_guard = self.in_process.lock().await;
        let _file_lock = FileLock::acquire_exclusive(&self.lock_path)?;
        atomic_write_json(&self.connection_path, &connection)?;
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let _process_guard = self.in_process.lock().await;
        let _file_lock = FileLock::acquire_exclusive(&self.lock_path)?;
        if let Err(error) = fs::remove_file(&self.connection_path)
            && error.kind() != ErrorKind::NotFound
        {
            return Err(error.into());
        }
        Ok(())
    }
}

// ----- File primitives ------------------------------------------------------

struct FileLock(File);

impl FileLock {
    fn acquire_exclusive(path: &Path) -> std::io::Result<Self> {
        let file = open_lock_file(path)?;
        FileExt::lock(&file)?;
        Ok(Self(file))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn atomic_write_json<T: Serialize>(target: &Path, value: &T) -> std::io::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "target path has no parent"))?;
    fs::create_dir_all(parent)?;

    let mut tmp = NamedTempFile::new_in(parent)?;
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
    {
        use std::io::Write;
        tmp.as_file_mut().write_all(body.as_bytes())?;
        tmp.as_file_mut().write_all(b"\n")?;
        tmp.as_file_mut().sync_all()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    tmp.persist(target).map_err(|e| e.error)?;

    #[cfg(unix)]
    {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, AuthError> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let value = serde_json::from_str::<T>(&content)
                .map_err(|e| AuthError::Malformed(e.to_string()))?;
            Ok(Some(value))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_persisted_base_url(auth_path: &Path) -> Option<String> {
    let content = fs::read_to_string(auth_path).ok()?;
    let record: AuthRecord = serde_json::from_str(&content).ok()?;
    Some(record.base_url)
}

fn resolve_base_url(persisted: Option<String>) -> String {
    std::env::var("OPENSTEER_CLOUD_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or(persisted)
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("config directory not found"))?;
    let dir = base.join("opensteer-cloud");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

// ----- Wire types -----------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DeviceStartResponse {
    device_code: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
    interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct CloudAgent {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct AgentListResponse {
    #[serde(rename = "cloudAgents")]
    cloud_agents: Vec<CloudAgent>,
}

#[derive(Debug, Deserialize)]
struct AgentCreateResponse {
    #[serde(rename = "cloudAgent")]
    cloud_agent: CloudAgent,
}

#[derive(Debug, Deserialize)]
struct WorkspaceBootstrapResponse {
    workspace: Option<WorkspaceResponse>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceResponse {
    id: String,
    #[serde(rename = "sandboxId")]
    sandbox_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RunFileReadResponse {
    #[serde(rename = "contentBase64")]
    content_base64: String,
}

#[derive(Debug, Deserialize)]
struct RunMutationResponse {}

#[derive(Debug, Deserialize)]
struct RunFileListResponse {
    entries: Vec<RunFileEntry>,
}

#[derive(Debug, Deserialize)]
struct RunFileEntry {
    path: String,
    #[serde(rename = "type")]
    entry_type: String,
}

#[derive(Debug, Deserialize)]
struct RunPatchResponse {
    ok: bool,
    #[serde(rename = "exitCode")]
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum RunStreamEvent {
    #[serde(rename = "stdout")]
    Stdout { chunk: String },
    #[serde(rename = "stderr")]
    Stderr { chunk: String },
    #[serde(rename = "exit")]
    Exit {
        #[serde(rename = "exitCode")]
        exit_code: Option<i32>,
        #[serde(rename = "timedOut")]
        _timed_out: bool,
    },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Debug, Serialize)]
struct TemplateDescriptor<'a> {
    id: &'a str,
    name: &'a str,
    source: &'a str,
}

#[derive(Debug, Clone)]
struct TemplateSummary {
    id: String,
    name: String,
    path: PathBuf,
    description: String,
    score: i32,
}

// ----- Templates ------------------------------------------------------------

fn template_search(query: &str) -> Result<()> {
    let templates = search_templates(query)?;
    if templates.is_empty() {
        println!("No templates found.");
        return Ok(());
    }
    for template in templates {
        println!(
            "{}\t{}\t{}",
            template.id, template.name, template.description
        );
    }
    Ok(())
}

fn template_inspect(id: &str) -> Result<()> {
    let template = find_template(id)?;
    println!("id: {}", template.id);
    println!("name: {}", template.name);
    println!("path: {}", template.path.display());
    println!();
    println!("{}", read_template_readme(&template.path)?);
    Ok(())
}

fn template_apply(id: &str) -> Result<()> {
    let template = find_template(id)?;
    let cwd = std::env::current_dir()?;
    copy_template(&template.path, &cwd)?;
    let opensteer_dir = cwd.join(".opensteer");
    fs::create_dir_all(&opensteer_dir)?;
    fs::write(
        cwd.join(TEMPLATE_DESCRIPTOR_PATH),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&TemplateDescriptor {
                id: &template.id,
                name: &template.name,
                source: &template.path.display().to_string(),
            })?
        ),
    )?;
    println!("Applied template {} into {}", template.id, cwd.display());
    Ok(())
}

fn search_templates(query: &str) -> Result<Vec<TemplateSummary>> {
    let query_terms = query_terms(query);
    let root = template_root()?;
    let mut templates = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if !id.ends_with("-pack") {
            continue;
        }
        let path = entry.path();
        let readme = read_template_readme(&path).unwrap_or_default();
        let haystack = format!("{id}\n{readme}").to_lowercase();
        let score = if query_terms.is_empty() {
            1
        } else {
            query_terms
                .iter()
                .map(|term| haystack.matches(term).count() as i32)
                .sum()
        };
        if score > 0 {
            templates.push(TemplateSummary {
                name: id.trim_end_matches("-pack").replace('-', " "),
                id,
                path,
                description: first_readme_sentence(&readme),
                score,
            });
        }
    }
    templates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    Ok(templates)
}

fn find_template(id: &str) -> Result<TemplateSummary> {
    let templates = search_templates(id)?;
    templates
        .into_iter()
        .find(|template| template.id == id || template.id.trim_end_matches("-pack") == id)
        .ok_or_else(|| anyhow!("template not found: {id}"))
}

fn template_root() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("OPENSTEER_TEMPLATE_REPO") {
        let path = PathBuf::from(value);
        if path.exists() {
            return Ok(path);
        }
    }
    let local = PathBuf::from("/Users/timjang/Developer/trendup/agent-packs");
    if local.exists() {
        return Ok(local);
    }
    let mut cwd = std::env::current_dir()?;
    loop {
        let candidate = cwd.join("agent-packs");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !cwd.pop() {
            break;
        }
    }
    Err(anyhow!(
        "template repo not found; set OPENSTEER_TEMPLATE_REPO to the agent-packs directory"
    ))
}

fn read_template_readme(path: &Path) -> Result<String> {
    fs::read_to_string(path.join("README.md"))
        .or_else(|_| fs::read_to_string(path.join("CLAUDE.md")))
        .with_context(|| format!("template {} has no README.md or CLAUDE.md", path.display()))
}

fn copy_template(source: &Path, destination: &Path) -> Result<()> {
    let mut created_dirs = HashSet::new();
    copy_dir_recursive(source, destination, source, &mut created_dirs)
}

fn copy_dir_recursive(
    root: &Path,
    destination: &Path,
    current: &Path,
    created_dirs: &mut HashSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root)?;
        if should_skip_template_path(relative) {
            continue;
        }
        let target = destination.join(relative);
        if entry.file_type()?.is_dir() {
            if created_dirs.insert(target.clone()) {
                fs::create_dir_all(&target)?;
            }
            copy_dir_recursive(root, destination, &path, created_dirs)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&path, &target)
                .with_context(|| format!("failed to copy {}", relative.display()))?;
        }
    }
    Ok(())
}

fn should_skip_template_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    if text == ".git"
        || text.starts_with(".git/")
        || text == ".local"
        || text.starts_with(".local/")
        || text.starts_with("node_modules/")
        || text.contains("/__pycache__/")
        || text.ends_with(".pyc")
        || text.ends_with(".log")
        || text.ends_with(".db")
        || text.ends_with(".db-wal")
        || text.ends_with(".db-shm")
        || text == ".DS_Store"
        || text.starts_with(".env")
        || text == ".claude/scheduled_tasks.lock"
    {
        return true;
    }
    false
}

fn query_terms(query: &str) -> Vec<String> {
    query
        .split(|c: char| !c.is_alphanumeric())
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .map(|term| term.to_lowercase())
        .collect()
}

fn first_readme_sentence(readme: &str) -> String {
    readme
        .lines()
        .find(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("```")
        })
        .map(|line| line.trim().trim_matches('*').to_string())
        .unwrap_or_default()
}

// ----- Misc helpers ---------------------------------------------------------

fn api_url(base_url: &str, path: &str) -> Result<String> {
    let base = base_url.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(format!("{base}{path}"))
}

fn is_opensteer_run_invocation() -> bool {
    std::env::args()
        .next()
        .and_then(|value| {
            Path::new(&value)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .as_deref()
        == Some("opensteer-run")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
