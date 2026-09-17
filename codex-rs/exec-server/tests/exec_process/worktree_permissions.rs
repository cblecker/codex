use super::collect_process_output_from_events;
use super::common;
use anyhow::Result;
use codex_exec_server::Environment;
use codex_exec_server::ExecParams;
use codex_exec_server::ExecServerRuntimePaths;
use codex_exec_server::FileSystemSandboxContext;
use codex_exec_server::ProcessId;
use codex_exec_server::WindowsSandboxSelection;
use codex_exec_server::WriteFileOptions;
use codex_http_client::HttpClientFactory;
use codex_http_client::OutboundProxyPolicy;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_path_uri::PathUri;
use pretty_assertions::assert_eq;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use test_case::test_case;

#[derive(Clone, Copy)]
enum Transport {
    Local,
    Remote,
}

fn git(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(cwd)
        .envs(git_env())
        .args(args)
        .output()?;
    assert!(output.status.success(), "{output:?}");
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn git_env() -> HashMap<String, String> {
    HashMap::from([
        (
            "GIT_CONFIG_GLOBAL".into(),
            if cfg!(windows) { "NUL" } else { "/dev/null" }.into(),
        ),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_AUTHOR_NAME".into(), "Test".into()),
        ("GIT_COMMITTER_NAME".into(), "Test".into()),
        ("GIT_AUTHOR_EMAIL".into(), "test@example.com".into()),
        ("GIT_COMMITTER_EMAIL".into(), "test@example.com".into()),
    ])
}

#[test_case(Transport::Local; "local")]
#[test_case(Transport::Remote; "remote")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linked_worktree_git_writes_follow_current_explicit_grant(
    transport: Transport,
) -> Result<()> {
    if let Some(warning) = codex_sandboxing::system_bwrap_warning(&PermissionProfile::read_only()) {
        eprintln!("skipping sandbox test: {warning}");
        return Ok(());
    }
    let server = match transport {
        Transport::Local => None,
        Transport::Remote => Some(common::exec_server::exec_server().await?),
    };
    let (exe, linux_exe) = common::current_test_binary_helper_paths()?;
    let environment = Environment::create(
        server
            .as_ref()
            .map(|server| server.websocket_url().to_string()),
        ExecServerRuntimePaths::new(exe, linux_exe)?,
        HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
    )?;
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    git(&root, &["init", "primary"])?;
    let primary = root.join("primary");
    git(&primary, &["commit", "--allow-empty", "-m", "initial"])?;
    git(
        &primary,
        &["worktree", "add", "-b", "linked", "../linked with spaces"],
    )?;
    let checkout = root.join("linked with spaces");
    std::fs::create_dir(checkout.join("nested"))?;
    let cwd = PathUri::from_host_native_path(checkout.join("nested"))?;
    let git_dir = std::path::PathBuf::from(git(&checkout, &["rev-parse", "--absolute-git-dir"])?);
    // No temporary-directory grants: both administrative destinations must be
    // authorized solely through the linked checkout's explicit `.git` entry.
    for (attempt, grant) in [false, true, false].into_iter().enumerate() {
        let mut entries = vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::project_roots(/*subpath*/ None),
                },
                FileSystemAccessMode::Write,
            ),
        ];
        if grant {
            entries.push(FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::project_roots(Some(".git".into())),
                },
                FileSystemAccessMode::Write,
            ));
        }
        let mut sandbox = FileSystemSandboxContext::from_permission_profile(
            PermissionProfile::from_runtime_permissions(
                &FileSystemSandboxPolicy::restricted(entries),
                NetworkSandboxPolicy::Restricted,
            ),
            cwd.clone(),
        );
        sandbox.workspace_roots = vec![PathUri::from_host_native_path(&checkout)?];
        if cfg!(windows) {
            sandbox.windows_sandbox_selection = WindowsSandboxSelection::RestrictedToken;
        }
        for path in [
            git_dir.join("test-write"),
            primary.join(".git/test-write"),
            primary.join("source.txt"),
        ] {
            let result = environment
                .get_filesystem()
                .write_file(
                    &PathUri::from_host_native_path(&path)?,
                    b"test".to_vec(),
                    WriteFileOptions::default(),
                    Some(&sandbox),
                )
                .await;
            assert_eq!(
                result.is_ok(),
                grant && path != primary.join("source.txt"),
                "{path:?}: {result:?}"
            );
        }
        std::fs::write(checkout.join("nested/file"), attempt.to_string())?;
        for args in [vec!["add", "file"], vec!["commit", "-m", "sandbox commit"]] {
            let session = environment
                .get_exec_backend()
                .start(ExecParams {
                    metadata: Default::default(),
                    process_id: ProcessId::from(format!("worktree-{attempt}-{}", args[0])),
                    argv: std::iter::once("git")
                        .chain(args)
                        .map(str::to_owned)
                        .collect(),
                    cwd: cwd.clone(),
                    shell_snapshot: None,
                    env_policy: None,
                    env: git_env(),
                    tty: false,
                    pipe_stdin: false,
                    arg0: None,
                    sandbox: Some(sandbox.clone()),
                    enforce_managed_network: false,
                    managed_network: None,
                    network_proxy: None,
                })
                .await?;
            let output = collect_process_output_from_events(session.process).await?;
            assert_eq!(output.2 == Some(0), grant, "{output:?}");
        }
    }
    Ok(())
}
