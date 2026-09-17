//! Validates repository identity and discovery across linked checkout layouts.

use super::*;
use pretty_assertions::assert_eq;

fn repository_with_linked_checkout() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("temporary repository");
    let primary = root.path().join("primary");
    let linked = root.path().join("linked");
    let admin = primary.join(".git").join("worktrees").join("linked");
    fs::create_dir_all(primary.join("nested")).expect("primary nested directory");
    fs::create_dir_all(linked.join("nested")).expect("linked nested directory");
    fs::create_dir_all(&admin).expect("worktree administrative directory");
    fs::write(primary.join(".git/HEAD"), "ref: refs/heads/main\n")
        .expect("primary repository HEAD");
    fs::write(admin.join("commondir"), "../..\n").expect("common directory");
    fs::write(
        admin.join("gitdir"),
        format!("{}\n", linked.join(".git").display()),
    )
    .expect("linked checkout backlink");
    fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .expect("linked checkout git file");
    (root, primary, linked)
}

#[test]
fn repository_identity_is_shared_by_primary_and_linked_checkouts() {
    let (_root, primary, linked) = repository_with_linked_checkout();
    let primary_cwd = canonicalize_native(primary.join("nested")).expect("primary cwd");
    let linked_cwd = canonicalize_native(linked.join("nested")).expect("linked cwd");
    let expected = RepositoryIdentity {
        common_dir: AbsolutePathBuf::from_absolute_path_checked(
            canonicalize_native(primary.join(".git")).expect("common git directory"),
        )
        .expect("absolute common directory"),
        relative_cwd: PathBuf::from("nested"),
        primary_root: AbsolutePathBuf::from_absolute_path_checked(
            canonicalize_native(&primary).expect("primary checkout"),
        )
        .expect("absolute primary checkout"),
    };

    assert_eq!(repository_identity(&primary_cwd), Some(expected.clone()));
    assert_eq!(repository_identity(&linked_cwd), Some(expected));
    assert_eq!(
        linked_worktree_cwds(&linked_cwd),
        Some(vec![linked_cwd, primary_cwd])
    );
}

#[cfg(unix)]
#[test]
fn linked_worktree_discovery_preserves_logical_working_directory_aliases() {
    let (root, primary, linked) = repository_with_linked_checkout();
    let alias = root.path().join("primary-alias");
    std::os::unix::fs::symlink(&primary, &alias).expect("checkout alias");
    let logical_cwd = alias.join("nested");
    let canonical_cwd = fs::canonicalize(primary.join("nested")).expect("primary cwd");
    let linked_cwd = fs::canonicalize(linked.join("nested")).expect("linked cwd");

    assert_eq!(
        linked_worktree_cwds(&logical_cwd),
        Some(vec![logical_cwd, canonical_cwd, linked_cwd])
    );
}

#[test]
fn linked_worktree_discovery_rejects_mismatched_backlinks() {
    let (_root, primary, linked) = repository_with_linked_checkout();
    let primary_cwd = canonicalize_native(primary.join("nested")).expect("primary cwd");
    let admin = primary.join(".git").join("worktrees").join("linked");
    fs::write(
        admin.join("gitdir"),
        primary.join(".git").display().to_string(),
    )
    .expect("invalid worktree backlink");

    assert_eq!(repository_identity(&linked.join("nested")), None);
    assert_eq!(linked_worktree_git_dirs(&linked), None);
    assert_eq!(linked_worktree_cwds(&primary_cwd), Some(vec![primary_cwd]));
}

#[test]
fn linked_git_directories_accept_relative_pointers_and_spaces() {
    let (_root, primary, linked) = repository_with_linked_checkout();
    let original = primary.join(".git/worktrees/linked");
    let admin = primary.join(".git/worktrees/linked with spaces");
    fs::rename(original, &admin).unwrap();
    fs::write(
        linked.join(".git"),
        "gitdir: ../primary/.git/worktrees/linked with spaces\n",
    )
    .unwrap();
    let expected = LinkedWorktreeGitDirs {
        git_dir: AbsolutePathBuf::from_absolute_path(admin)
            .unwrap()
            .canonicalize()
            .unwrap(),
        common_dir: AbsolutePathBuf::from_absolute_path(primary.join(".git"))
            .unwrap()
            .canonicalize()
            .unwrap(),
    };
    assert_eq!(
        linked_worktree_git_dirs(&linked.join("nested")),
        Some(expected)
    );
    assert_eq!(linked_worktree_git_dirs(&primary), None);
}

#[test]
fn linked_git_directories_reject_invalid_metadata() {
    for contents in [
        "",
        "gitdir:",
        "not git",
        "gitdir: /missing\nextra",
        &"x".repeat(65_537),
    ] {
        let (_root, _primary, linked) = repository_with_linked_checkout();
        fs::write(linked.join(".git"), contents).unwrap();
        assert_eq!(linked_worktree_git_dirs(&linked), None);
    }
    let (_root, primary, linked) = repository_with_linked_checkout();
    fs::write(
        primary.join(".git/worktrees/linked/commondir"),
        "../../..\n",
    )
    .unwrap();
    assert_eq!(linked_worktree_git_dirs(&linked), None);
}

#[cfg(unix)]
#[test]
fn linked_git_directories_reject_symlinked_registration_and_metadata() {
    for relative in [
        ".git",
        ".git/worktrees",
        ".git/worktrees/linked",
        ".git/worktrees/linked/commondir",
        ".git/worktrees/linked/gitdir",
    ] {
        let (root, primary, linked) = repository_with_linked_checkout();
        let original = primary.join(relative);
        let outside = root.path().join("outside");
        fs::rename(&original, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &original).unwrap();
        assert_eq!(linked_worktree_git_dirs(&linked), None, "{relative}");
    }
    let (root, _primary, linked) = repository_with_linked_checkout();
    let dot_git = linked.join(".git");
    let outside = root.path().join("pointer");
    fs::rename(&dot_git, &outside).unwrap();
    std::os::unix::fs::symlink(&outside, &dot_git).unwrap();
    assert_eq!(linked_worktree_git_dirs(&linked), None);
}

#[cfg(unix)]
#[test]
fn linked_git_directories_reject_symlink_parent_traversal() {
    let (root, primary, linked) = repository_with_linked_checkout();
    let outside = root.path().join("outside");
    fs::create_dir_all(outside.join("nested")).unwrap();
    fs::create_dir(outside.join("linked")).unwrap();
    let alias = primary.join(".git/worktrees/alias");
    std::os::unix::fs::symlink(outside.join("nested"), &alias).unwrap();
    fs::write(
        linked.join(".git"),
        format!("gitdir: {}/../linked\n", alias.display()),
    )
    .unwrap();
    assert_eq!(linked_worktree_git_dirs(&linked), None);
}

#[test]
fn linked_git_directories_reject_multiline_pointer_fields() {
    let (_root, primary, linked) = repository_with_linked_checkout();
    let admin = primary.join(".git/worktrees/linked");
    for contents in [
        format!("gitdir: \n{}\n", admin.display()),
        format!("\ngitdir: {}\n", admin.display()),
    ] {
        fs::write(linked.join(".git"), contents).unwrap();
        assert_eq!(linked_worktree_git_dirs(&linked), None);
    }
    fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    fs::write(admin.join("commondir"), "\n../..\n").unwrap();
    assert_eq!(linked_worktree_git_dirs(&linked), None);
}

#[cfg(unix)]
#[test]
fn linked_worktree_discovery_rejects_relative_directory_symlink_escapes() {
    let (root, primary, linked) = repository_with_linked_checkout();
    let primary_cwd = fs::canonicalize(primary.join("nested")).expect("primary cwd");
    let outside = root.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");
    fs::remove_dir(linked.join("nested")).expect("remove linked nested directory");
    std::os::unix::fs::symlink(&outside, linked.join("nested")).expect("escaping symlink");

    assert_eq!(linked_worktree_cwds(&primary_cwd), Some(vec![primary_cwd]));
}
