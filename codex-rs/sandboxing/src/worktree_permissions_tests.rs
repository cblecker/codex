use super::*;
use codex_protocol::permissions::NetworkSandboxPolicy;
use pretty_assertions::assert_eq;
use std::fs;

struct Fixture {
    _temp: tempfile::TempDir,
    checkout: AbsolutePathBuf,
    common: AbsolutePathBuf,
    admin: AbsolutePathBuf,
    profile: PermissionProfile,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = AbsolutePathBuf::from_absolute_path(temp.path())
            .unwrap()
            .canonicalize()
            .unwrap();
        let checkout = root.join("linked with spaces");
        let common = root.join("primary/.git");
        let admin = common.join("worktrees/linked");
        fs::create_dir_all(checkout.join("nested")).unwrap();
        fs::create_dir_all(&admin).unwrap();
        fs::write(
            checkout.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        )
        .unwrap();
        fs::write(admin.join("commondir"), "../..\n").unwrap();
        fs::write(
            admin.join("gitdir"),
            format!("{}\n", checkout.join(".git").display()),
        )
        .unwrap();
        let policy = FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(checkout.clone().into(), FileSystemAccessMode::Write),
            FileSystemSandboxEntry::new(checkout.join(".git").into(), FileSystemAccessMode::Write),
        ]);
        Self {
            _temp: temp,
            checkout,
            common,
            admin,
            profile: PermissionProfile::from_runtime_permissions(
                &policy,
                NetworkSandboxPolicy::Restricted,
            ),
        }
    }

    fn restricted(&self, path: FileSystemPath, access: FileSystemAccessMode) -> PermissionProfile {
        let mut policy = self.profile.file_system_sandbox_policy();
        policy
            .entries
            .push(FileSystemSandboxEntry::new(path, access));
        PermissionProfile::from_runtime_permissions(&policy, NetworkSandboxPolicy::Restricted)
    }

    fn writable(&self, profile: PermissionProfile) -> Vec<bool> {
        let roots = profile
            .file_system_sandbox_policy()
            .get_writable_roots_with_cwd(&self.checkout);
        [
            self.admin.join("index.lock"),
            self.common.join("objects/new"),
            self.common.join("refs/heads/new"),
            self.common.parent().unwrap().join("source.txt"),
        ]
        .iter()
        .map(|path| roots.iter().any(|root| root.is_path_writable(path)))
        .collect()
    }
}

#[test]
fn explicit_grant_expands_from_nested_cwd_without_authorizing_source_checkout() {
    let f = Fixture::new();
    assert_eq!(f.writable(f.profile.clone()), vec![false; 4]);
    let expanded =
        with_worktree_git_write_permissions(f.profile.clone(), &f.checkout.join("nested"));
    assert_eq!(f.writable(expanded.clone()), vec![true, true, true, false]);
    assert_eq!(
        with_worktree_git_write_permissions(expanded.clone(), &f.checkout),
        expanded
    );
    let mut policy = f.profile.file_system_sandbox_policy();
    policy
        .entries
        .retain(|entry| entry.path != FileSystemPath::from(f.checkout.join(".git")));
    let revoked =
        PermissionProfile::from_runtime_permissions(&policy, NetworkSandboxPolicy::Restricted);
    assert_eq!(
        f.writable(with_worktree_git_write_permissions(revoked, &f.checkout)),
        vec![false; 4]
    );
}

#[test]
fn restrictions_on_logical_and_concrete_git_paths_survive_expansion() {
    let f = Fixture::new();
    for (path, access, expected) in [
        (
            f.checkout.join(".git/index.lock"),
            FileSystemAccessMode::Read,
            vec![false, true, true, false],
        ),
        (
            f.checkout.join(".git/objects"),
            FileSystemAccessMode::Deny,
            vec![true, false, true, false],
        ),
        (
            f.common.join("refs"),
            FileSystemAccessMode::Read,
            vec![true, true, false, false],
        ),
    ] {
        let profile = f.restricted(path.into(), access);
        let expanded = with_worktree_git_write_permissions(profile, &f.checkout);
        assert_eq!(f.writable(expanded.clone()), expected);
        if access == FileSystemAccessMode::Deny {
            let matcher = ReadDenyMatcher::try_new_for_local_paths(
                &expanded.file_system_sandbox_policy(),
                &f.checkout,
            )
            .unwrap()
            .unwrap();
            assert!(matcher.is_local_path_read_denied(&f.common.join("objects/new")));
        }
    }
}

#[test]
fn destination_ancestor_restrictions_and_ambiguous_projections_prevent_expansion() {
    let f = Fixture::new();
    for path in [
        f.common.clone(),
        f.admin.clone(),
        f.common.parent().unwrap().to_path_buf().try_into().unwrap(),
        f.checkout.join(".git/worktrees"),
    ] {
        for access in [FileSystemAccessMode::Read, FileSystemAccessMode::Deny] {
            let profile = f.restricted(path.clone().into(), access);
            assert_eq!(
                with_worktree_git_write_permissions(profile.clone(), &f.checkout),
                profile
            );
        }
    }
    let denied = f.restricted(f.checkout.join(".git").into(), FileSystemAccessMode::Deny);
    assert_eq!(
        with_worktree_git_write_permissions(denied.clone(), &f.checkout),
        denied
    );
}

#[test]
fn overlapping_globs_prevent_expansion_and_unrelated_globs_allow_it() {
    let f = Fixture::new();
    for pattern in [
        format!("{}/.git/objects/**", f.checkout.display()),
        "**/secret".into(),
    ] {
        let profile = f.restricted(
            FileSystemPath::GlobPattern { pattern },
            FileSystemAccessMode::Deny,
        );
        assert_eq!(
            with_worktree_git_write_permissions(profile.clone(), &f.checkout),
            profile
        );
    }
    let profile = f.restricted(
        FileSystemPath::GlobPattern {
            pattern: format!("{}/private/id_*", f.checkout.display()),
        },
        FileSystemAccessMode::Deny,
    );
    assert_eq!(
        f.writable(with_worktree_git_write_permissions(profile, &f.checkout)),
        vec![true, true, true, false]
    );
}

#[test]
fn resolution_revalidates_metadata_on_every_launch() {
    let f = Fixture::new();
    assert_eq!(
        f.writable(with_worktree_git_write_permissions(
            f.profile.clone(),
            &f.checkout
        )),
        vec![true, true, true, false]
    );
    fs::write(f.admin.join("gitdir"), f.common.display().to_string()).unwrap();
    assert_eq!(
        with_worktree_git_write_permissions(f.profile.clone(), &f.checkout),
        f.profile
    );
}

#[test]
fn native_preparation_carries_expanded_profile_for_process_and_filesystem_launchers() {
    use crate::SandboxCommand;
    use crate::SandboxManager;
    use crate::SandboxTransformRequest;
    use crate::SandboxType;
    use codex_protocol::config_types::WindowsSandboxLevel;
    use codex_utils_path_uri::PathUri;

    let f = Fixture::new();
    let cwd = PathUri::from_abs_path(&f.checkout.join("nested"));
    for manager in [
        SandboxManager::new(),
        SandboxManager::for_file_system_helpers(),
    ] {
        let request = manager
            .transform(SandboxTransformRequest {
                command: SandboxCommand {
                    program: "git".into(),
                    args: vec!["status".into()],
                    cwd: cwd.clone(),
                    env: Default::default(),
                    managed_network: None,
                    additional_permissions: None,
                },
                permissions: &f.profile,
                // This backend defers spawning, allowing native preparation to be
                // verified on every host without launching a nested OS sandbox.
                sandbox: SandboxType::WindowsRestrictedToken,
                enforce_managed_network: false,
                environment_id: None,
                network: None,
                sandbox_policy_cwd: &cwd,
                sandbox_exe: None,
                use_legacy_landlock: false,
                windows_sandbox_level: WindowsSandboxLevel::Disabled,
                windows_sandbox_private_desktop: false,
            })
            .unwrap();
        assert_eq!(
            f.writable(request.permission_profile),
            vec![true, true, true, false]
        );
    }
}
