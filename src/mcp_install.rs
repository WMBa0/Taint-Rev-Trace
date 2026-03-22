use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct BatchInstallReport {
    pub detected_clients: Vec<String>,
    pub changed_clients: Vec<ClientChange>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ClientChange {
    pub client_name: String,
    pub target_path: Option<PathBuf>,
    pub method: String,
}

impl BatchInstallReport {
    pub fn success_count(&self) -> usize {
        self.changed_clients.len()
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    #[allow(dead_code)]
    pub fn primary_path(&self) -> Option<PathBuf> {
        self.changed_clients
            .iter()
            .find_map(|change| change.target_path.clone())
    }

    pub fn summary_text(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!(
            "{} client(s) detected",
            self.detected_clients.len()
        ));
        parts.push(format!(
            "{} client(s) updated",
            self.changed_clients.len()
        ));
        if self.has_errors() {
            parts.push(format!("{} error(s)", self.errors.len()));
        }
        parts.join(", ")
    }

    pub fn detail_text(&self) -> String {
        let mut lines = Vec::new();
        if !self.changed_clients.is_empty() {
            let details = self
                .changed_clients
                .iter()
                .map(|change| format!("{} via {}", change.client_name, change.method))
                .collect::<Vec<_>>()
                .join("; ");
            lines.push(format!("updated: {details}"));
        }
        if !self.errors.is_empty() {
            lines.push(self.errors.join(" | "));
        }
        lines.join(" ")
    }
}

#[derive(Clone, Debug)]
enum ClientTarget {
    Json {
        client_name: &'static str,
        config_path: PathBuf,
        root_key: &'static str,
        detected: bool,
    },
    VscodeCli {
        client_name: &'static str,
        config_path: PathBuf,
        cli_path: PathBuf,
        detected: bool,
    },
    ClaudeCodeCli {
        client_name: &'static str,
        cli_path: PathBuf,
        detected: bool,
    },
    CodexCli {
        client_name: &'static str,
        cli_path: PathBuf,
        config_path: PathBuf,
        detected: bool,
    },
}

pub fn detect_any_global_mcp(server_name: &str) -> bool {
    detect_supported_clients()
        .into_iter()
        .any(|target| is_server_configured(&target, server_name))
}

pub fn detect_supported_client_names() -> Vec<String> {
    detect_supported_clients()
        .into_iter()
        .map(|target| match target {
            ClientTarget::Json { client_name, .. }
            | ClientTarget::VscodeCli { client_name, .. }
            | ClientTarget::ClaudeCodeCli { client_name, .. }
            | ClientTarget::CodexCli { client_name, .. } => client_name.to_string(),
        })
        .collect()
}

pub fn preferred_global_config_paths() -> Vec<PathBuf> {
    detect_supported_clients()
        .into_iter()
        .filter_map(|target| match target {
            ClientTarget::Json { config_path, .. }
            | ClientTarget::VscodeCli { config_path, .. }
            | ClientTarget::CodexCli { config_path, .. } => Some(config_path),
            ClientTarget::ClaudeCodeCli { .. } => None,
        })
        .collect()
}

pub fn install_to_detected_clients(
    server_name: &str,
    command: &str,
    args: &[String],
) -> BatchInstallReport {
    let launch = json!({
        "command": command,
        "args": args,
    });

    let mut report = BatchInstallReport {
        detected_clients: Vec::new(),
        changed_clients: Vec::new(),
        errors: Vec::new(),
    };

    for target in detect_supported_clients() {
        let client_name = target_name(&target).to_string();
        report.detected_clients.push(client_name.clone());

        let result = match &target {
            ClientTarget::Json {
                config_path,
                root_key,
                ..
            } => write_json_server_config(config_path, root_key, server_name, Some(&launch))
                .map(|path| ClientChange {
                    client_name: client_name.clone(),
                    target_path: Some(path),
                    method: "json config".to_string(),
                }),
            ClientTarget::VscodeCli {
                cli_path,
                config_path,
                ..
            } => add_vscode_cli_server(cli_path, server_name, command, args)
                .map(|_| ClientChange {
                    client_name: client_name.clone(),
                    target_path: Some(config_path.clone()),
                    method: "VS Code CLI".to_string(),
                })
                .or_else(|_| {
                    write_json_server_config(config_path, "servers", server_name, Some(&launch))
                        .map(|path| ClientChange {
                            client_name: client_name.clone(),
                            target_path: Some(path),
                            method: "json config fallback".to_string(),
                        })
                }),
            ClientTarget::ClaudeCodeCli { cli_path, .. } => {
                add_claude_code_server(cli_path, server_name, &launch).map(|_| ClientChange {
                    client_name: client_name.clone(),
                    target_path: None,
                    method: "claude mcp add-json".to_string(),
                })
            }
            ClientTarget::CodexCli {
                cli_path,
                config_path,
                ..
            } => add_codex_server(cli_path, server_name, command, args).map(|_| ClientChange {
                client_name: client_name.clone(),
                target_path: Some(config_path.clone()),
                method: "codex mcp add".to_string(),
            }),
        };

        match result {
            Ok(change) => report.changed_clients.push(change),
            Err(_) => report.errors.push(format!("{client_name}: install failed")),
        }
    }

    report
}

pub fn remove_from_detected_clients(server_name: &str) -> BatchInstallReport {
    let mut report = BatchInstallReport {
        detected_clients: Vec::new(),
        changed_clients: Vec::new(),
        errors: Vec::new(),
    };

    for target in detect_supported_clients() {
        let client_name = target_name(&target).to_string();
        report.detected_clients.push(client_name.clone());

        let result = match &target {
            ClientTarget::Json {
                config_path,
                root_key,
                ..
            } => write_json_server_config(config_path, root_key, server_name, None).map(|path| {
                ClientChange {
                    client_name: client_name.clone(),
                    target_path: Some(path),
                    method: "json config".to_string(),
                }
            }),
            ClientTarget::VscodeCli { config_path, .. } => {
                write_json_server_config(config_path, "servers", server_name, None).map(|path| {
                    ClientChange {
                        client_name: client_name.clone(),
                        target_path: Some(path),
                        method: "json config".to_string(),
                    }
                })
            }
            ClientTarget::ClaudeCodeCli { cli_path, .. } => {
                remove_claude_code_server(cli_path, server_name).map(|_| ClientChange {
                    client_name: client_name.clone(),
                    target_path: None,
                    method: "claude mcp remove".to_string(),
                })
            }
            ClientTarget::CodexCli {
                cli_path,
                config_path,
                ..
            } => remove_codex_server(cli_path, server_name).map(|_| ClientChange {
                client_name: client_name.clone(),
                target_path: Some(config_path.clone()),
                method: "codex mcp remove".to_string(),
            }),
        };

        match result {
            Ok(change) => report.changed_clients.push(change),
            Err(_) => report.errors.push(format!("{client_name}: remove failed")),
        }
    }

    report
}

fn detect_supported_clients() -> Vec<ClientTarget> {
    let mut targets = Vec::new();

    if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
        let vscode_dir = appdata.join("Code");
        if vscode_dir.exists() {
            targets.push(if let Some(cli) = find_cli(&["code.cmd", "code"], &[
                appdata
                    .parent()
                    .unwrap_or(&appdata)
                    .join("Local")
                    .join("Programs")
                    .join("Microsoft VS Code")
                    .join("bin")
                    .join("code.cmd"),
                PathBuf::from(r"C:\Program Files\Microsoft VS Code\bin\code.cmd"),
            ]) {
                ClientTarget::VscodeCli {
                    client_name: "VS Code",
                    config_path: vscode_dir.join("User").join("mcp.json"),
                    cli_path: cli,
                    detected: true,
                }
            } else {
                ClientTarget::Json {
                    client_name: "VS Code",
                    config_path: vscode_dir.join("User").join("mcp.json"),
                    root_key: "servers",
                    detected: true,
                }
            });
        }

        let code_insiders_dir = appdata.join("Code - Insiders");
        if code_insiders_dir.exists() {
            targets.push(if let Some(cli) = find_cli(&["code-insiders.cmd", "code-insiders"], &[
                appdata
                    .parent()
                    .unwrap_or(&appdata)
                    .join("Local")
                    .join("Programs")
                    .join("Microsoft VS Code Insiders")
                    .join("bin")
                    .join("code-insiders.cmd"),
            ]) {
                ClientTarget::VscodeCli {
                    client_name: "VS Code Insiders",
                    config_path: code_insiders_dir.join("User").join("mcp.json"),
                    cli_path: cli,
                    detected: true,
                }
            } else {
                ClientTarget::Json {
                    client_name: "VS Code Insiders",
                    config_path: code_insiders_dir.join("User").join("mcp.json"),
                    root_key: "servers",
                    detected: true,
                }
            });
        }

        let claude_dir = appdata.join("Claude");
        if claude_dir.exists()
            || std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .map(|path| path.join("AnthropicClaude").exists())
                .unwrap_or(false)
        {
            targets.push(ClientTarget::Json {
                client_name: "Claude Desktop",
                config_path: claude_dir.join("claude_desktop_config.json"),
                root_key: "mcpServers",
                detected: true,
            });
        }
    }

    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        let cursor_dir = home.join(".cursor");
        if cursor_dir.exists() {
            targets.push(ClientTarget::Json {
                client_name: "Cursor",
                config_path: cursor_dir.join("mcp.json"),
                root_key: "mcpServers",
                detected: true,
            });
        }

        let windsurf_dir = home.join(".codeium").join("windsurf");
        if windsurf_dir.exists() {
            targets.push(ClientTarget::Json {
                client_name: "Windsurf",
                config_path: windsurf_dir.join("mcp_config.json"),
                root_key: "mcpServers",
                detected: true,
            });
        }

        let codex_config = home.join(".codex").join("config.toml");
        if codex_config.exists()
            || find_cli(&["codex.exe", "codex"], &[]).is_some()
        {
            if let Some(cli) = find_cli(&["codex.exe", "codex"], &[]) {
                targets.push(ClientTarget::CodexCli {
                    client_name: "Codex CLI",
                    cli_path: cli,
                    config_path: codex_config,
                    detected: true,
                });
            }
        }
    }

    if let Some(cli) = find_cli(&["claude.cmd", "claude"], &[]) {
        targets.push(ClientTarget::ClaudeCodeCli {
            client_name: "Claude Code",
            cli_path: cli,
            detected: true,
        });
    }

    targets
        .into_iter()
        .filter(|target| match target {
            ClientTarget::Json { detected, .. }
            | ClientTarget::VscodeCli { detected, .. }
            | ClientTarget::ClaudeCodeCli { detected, .. }
            | ClientTarget::CodexCli { detected, .. } => *detected,
        })
        .collect()
}

fn target_name(target: &ClientTarget) -> &'static str {
    match target {
        ClientTarget::Json { client_name, .. }
        | ClientTarget::VscodeCli { client_name, .. }
        | ClientTarget::ClaudeCodeCli { client_name, .. }
        | ClientTarget::CodexCli { client_name, .. } => client_name,
    }
}

fn is_server_configured(target: &ClientTarget, server_name: &str) -> bool {
    match target {
        ClientTarget::Json {
            config_path,
            root_key,
            ..
        } => json_config_contains_server(config_path, root_key, server_name),
        ClientTarget::VscodeCli {
            config_path,
            ..
        } => json_config_contains_server(config_path, "servers", server_name),
        ClientTarget::CodexCli {
            cli_path,
            config_path,
            ..
        } => codex_server_exists(cli_path, server_name)
            || toml_config_contains_server(config_path, server_name),
        ClientTarget::ClaudeCodeCli { cli_path, .. } => claude_code_server_exists(cli_path, server_name),
    }
}

fn json_config_contains_server(path: &Path, root_key: &str, server_name: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(root) = serde_json::from_str::<Value>(&content) else {
        return false;
    };
    root.get(root_key)
        .and_then(Value::as_object)
        .map(|servers| servers.contains_key(server_name))
        .unwrap_or(false)
}

fn toml_config_contains_server(path: &Path, server_name: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let needle = format!("[mcp_servers.{server_name}]");
    content.contains(&needle)
}

fn claude_code_server_exists(cli_path: &Path, server_name: &str) -> bool {
    Command::new(cli_path)
        .args(["mcp", "get", server_name])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn codex_server_exists(cli_path: &Path, server_name: &str) -> bool {
    Command::new(cli_path)
        .args(["mcp", "get", server_name])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn add_vscode_cli_server(
    cli_path: &Path,
    server_name: &str,
    command: &str,
    args: &[String],
) -> Result<()> {
    let payload = serde_json::to_string(&json!({
        "name": server_name,
        "command": command,
        "args": args,
    }))?;
    run_command_checked(
        cli_path,
        vec!["--add-mcp".to_string(), payload],
        "VS Code CLI install",
    )
}

fn add_claude_code_server(cli_path: &Path, server_name: &str, launch: &Value) -> Result<()> {
    run_command_checked(
        cli_path,
        vec![
            "mcp".to_string(),
            "add-json".to_string(),
            server_name.to_string(),
            serde_json::to_string(launch)?,
            "--scope".to_string(),
            "user".to_string(),
        ],
        "Claude Code install",
    )
}

fn remove_claude_code_server(cli_path: &Path, server_name: &str) -> Result<()> {
    run_command_checked(
        cli_path,
        vec![
            "mcp".to_string(),
            "remove".to_string(),
            server_name.to_string(),
            "--scope".to_string(),
            "user".to_string(),
        ],
        "Claude Code remove",
    )
}

fn add_codex_server(cli_path: &Path, server_name: &str, command: &str, args: &[String]) -> Result<()> {
    let mut cmd_args = vec![
        "mcp".to_string(),
        "add".to_string(),
        server_name.to_string(),
        "--".to_string(),
        command.to_string(),
    ];
    cmd_args.extend(args.iter().cloned());
    run_command_checked(cli_path, cmd_args, "Codex CLI install")
}

fn remove_codex_server(cli_path: &Path, server_name: &str) -> Result<()> {
    run_command_checked(
        cli_path,
        vec!["mcp".to_string(), "remove".to_string(), server_name.to_string()],
        "Codex CLI remove",
    )
}

fn run_command_checked(cli_path: &Path, args: Vec<String>, context: &str) -> Result<()> {
    let output = Command::new(cli_path)
        .args(&args)
        .output()
        .with_context(|| format!("{context}: failed to launch CLI"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    bail!("{context}: {detail}")
}

fn write_json_server_config(
    path: &Path,
    root_key: &str,
    server_name: &str,
    launch: Option<&Value>,
) -> Result<PathBuf> {
    let mut root = if path.exists() {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str::<Value>(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !root.is_object() {
        root = json!({});
    }
    let object = root.as_object_mut().expect("json root object");

    let servers_value = object
        .entry(root_key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !servers_value.is_object() {
        *servers_value = Value::Object(Map::new());
    }

    let servers = servers_value.as_object_mut().expect("server object");
    if let Some(launch) = launch {
        servers.insert(server_name.to_string(), launch.clone());
    } else {
        servers.remove(server_name);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&root)?)?;
    Ok(path.to_path_buf())
}

fn find_cli(names: &[&str], extra_candidates: &[PathBuf]) -> Option<PathBuf> {
    let mut candidates = extra_candidates.to_vec();
    for name in names {
        candidates.push(PathBuf::from(name));
        if cfg!(windows) {
            if let Some(found) = where_on_path(name) {
                candidates.push(found);
            }
        }
    }

    candidates.into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("--help")
            .output()
            .map(|output| output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty())
            .unwrap_or(false)
    })
}

fn where_on_path(name: &str) -> Option<PathBuf> {
    let output = Command::new("where.exe").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let first = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    Some(PathBuf::from(first))
}
