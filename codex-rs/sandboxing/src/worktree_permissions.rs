//! Expand explicit linked-worktree `.git` grants only at native execution boundaries.

use codex_git_utils::linked_worktree_git_dirs;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxKind;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::ReadDenyMatcher;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::path::Path;

/// Honors explicit `.git` write grants for validated linked worktrees on this executor.
/// Call after materializing workspace rules, and retain the result only for this launch.
pub fn with_worktree_git_write_permissions(
    permissions: PermissionProfile,
    cwd: &Path,
) -> PermissionProfile {
    let (mut policy, network) = permissions.to_runtime_permissions();
    if policy.kind != FileSystemSandboxKind::Restricted {
        return permissions;
    }
    let original = policy.clone();
    for entry in &original.entries {
        let FileSystemPath::Path { path } = &entry.path else {
            continue;
        };
        let Ok(dot_git) = path.to_abs_path() else {
            continue;
        };
        if entry.access != FileSystemAccessMode::Write
            || dot_git.file_name().is_none_or(|name| name != ".git")
            || !original.can_write_local_path_with_cwd(&dot_git, cwd)
        {
            continue;
        }
        if let Some(entries) = worktree_grants(&policy, &dot_git, cwd) {
            for entry in entries {
                if !policy.entries.contains(&entry) {
                    policy.entries.push(entry);
                }
            }
        }
    }
    PermissionProfile::from_runtime_permissions_with_enforcement(
        permissions.enforcement(),
        &policy,
        network,
    )
}

fn worktree_grants(
    policy: &FileSystemSandboxPolicy,
    dot_git: &AbsolutePathBuf,
    cwd: &Path,
) -> Option<Vec<FileSystemSandboxEntry>> {
    let matcher = ReadDenyMatcher::try_new_for_local_paths(policy, cwd).ok()?;
    if matcher.is_some_and(|matcher| matcher.is_local_path_read_denied(dot_git)) {
        return None;
    }
    let dirs = linked_worktree_git_dirs(&dot_git.parent()?)?;
    let dot_git = dot_git.canonicalize().ok()?;
    let destinations = [&dirs.git_dir, &dirs.common_dir];
    // A wildcard that can overlap a translated tree cannot be safely relocated
    // by replacing a string prefix. Preserve the original profile in that case.
    for pattern in policy.get_unreadable_globs_with_cwd(cwd) {
        let prefix = pattern.split(['*', '?', '[', ']', '{', '}']).next()?;
        let prefix = Path::new(prefix).parent()?;
        let prefix = canonicalize_existing_prefix(prefix)?;
        if [&dot_git, &dirs.git_dir, &dirs.common_dir]
            .iter()
            .any(|root| root.starts_with(&prefix) || prefix.starts_with(root))
        {
            return None;
        }
    }
    let mut grants: Vec<_> = destinations
        .iter()
        .map(|path| {
            FileSystemSandboxEntry::new((*path).clone().into(), FileSystemAccessMode::Write)
        })
        .collect();
    for entry in &policy.entries {
        if entry.access.can_write() {
            continue;
        }
        let path = match &entry.path {
            FileSystemPath::Path { path } => {
                canonicalize_existing_prefix(&path.to_abs_path().ok()?)?
            }
            FileSystemPath::GlobPattern { .. }
            | FileSystemPath::Special {
                value: FileSystemSpecialPath::Root | FileSystemSpecialPath::Minimal,
            } => continue,
            // Unmaterialized restrictions have no unambiguous native target.
            FileSystemPath::Special { .. } => return None,
        };
        // Legacy profiles include a default, skippable `.git` read rule. The
        // explicit effective write grant above supersedes that default.
        if entry.skips_missing_path() && path == dot_git {
            continue;
        }
        if destinations.iter().any(|root| root.starts_with(&path)) {
            return None;
        }
        if let Ok(suffix) = path.strip_prefix(&dot_git) {
            for destination in destinations {
                let projected = destination.join(suffix);
                if destinations.iter().any(|root| root.starts_with(&projected)) {
                    return None;
                }
                // An existing concrete grant could otherwise override the
                // projected restriction by being more specific.
                for candidate in &policy.entries {
                    if candidate.access.can_write()
                        && let FileSystemPath::Path { path } = &candidate.path
                        && canonicalize_existing_prefix(&path.to_abs_path().ok()?)?
                            .starts_with(&projected)
                    {
                        return None;
                    }
                }
                grants.push(FileSystemSandboxEntry::new(projected.into(), entry.access));
            }
        }
    }
    Some(grants)
}

fn canonicalize_existing_prefix(path: &Path) -> Option<AbsolutePathBuf> {
    for ancestor in path.ancestors() {
        if let Ok(canonical) = AbsolutePathBuf::from_absolute_path(ancestor)
            .ok()?
            .canonicalize()
        {
            return Some(canonical.join(path.strip_prefix(ancestor).ok()?));
        }
    }
    None
}

#[cfg(test)]
#[path = "worktree_permissions_tests.rs"]
mod tests;
