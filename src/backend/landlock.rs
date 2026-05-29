use std::env;
use std::ffi::CString;
use std::fs;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;
use crate::cli::Mode;
use crate::policy::Policy;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// Access rights that can apply to a rule targeting a regular file. Directory
/// rights (MAKE_*, REMOVE_*, READ_DIR, REFER) are invalid on a file fd.
const FILE_ACCESS: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("agent-locker Landlock backend currently supports x86_64 only");

#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

#[repr(C)]
struct LandlockRulesetAttrV1 {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

pub fn exec(policy: &Policy) -> Result<()> {
    ensure_mode_paths(policy)?;

    let abi = landlock_abi_version()?;
    let handled_access_fs = handled_access_mask(abi);
    let ro_access = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
    let rw_access = rw_access_mask(abi);
    // Landlock rejects directory-only access bits on a rule whose target is a
    // regular file, so file rules use only the file-applicable rights.
    let rw_file_access = rw_access & FILE_ACCESS;

    let attr = LandlockRulesetAttrV1 { handled_access_fs };
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr,
            size_of::<LandlockRulesetAttrV1>(),
            0,
        ) as i32
    };
    if ruleset_fd < 0 {
        return Err(last_os_error("landlock_create_ruleset failed"));
    }

    let result = (|| -> Result<()> {
        add_path_rule(ruleset_fd, Path::new("/"), ro_access)?;

        for path in writable_rule_paths(policy)? {
            let access = if path.is_dir() {
                rw_access
            } else {
                rw_file_access
            };
            add_path_rule(ruleset_fd, &path, access)?;
        }

        let prctl_rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if prctl_rc != 0 {
            return Err(last_os_error("prctl(PR_SET_NO_NEW_PRIVS) failed"));
        }

        // Block TIOCSTI terminal-input injection before locking in the ruleset.
        // Landlock cannot express this (see the seccomp module), so a small
        // seccomp filter handles it; it requires the NO_NEW_PRIVS just set.
        super::seccomp::install_tiocsti_block()?;

        let restrict_rc =
            unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) as i32 };
        if restrict_rc != 0 {
            return Err(last_os_error("landlock_restrict_self failed"));
        }

        let mut cmd = Command::new(&policy.command.program);
        cmd.args(&policy.command.args);
        let err = cmd.exec();
        Err(format!("failed to exec command: {err}").into())
    })();

    unsafe {
        libc::close(ruleset_fd);
    }

    result
}

fn writable_rule_paths(policy: &Policy) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for path in &policy.write_dirs {
        let rule_path = rule_path_for_write(path)?;
        if !out.contains(&rule_path) {
            out.push(rule_path);
        }
    }
    Ok(out)
}

fn rule_path_for_write(path: &Path) -> Result<PathBuf> {
    // An existing path (directory or file) gets a rule applied directly to it.
    // Landlock supports file-level rules, so a writable file does not need its
    // whole parent directory opened up.
    if path.exists() {
        return Ok(path.to_path_buf());
    }

    if let Some(parent) = path.parent() {
        if parent.exists() {
            return Ok(parent.to_path_buf());
        }
    }

    Err(format!(
        "writable path does not exist and has no existing parent: {}",
        path.display()
    )
    .into())
}

fn ensure_mode_paths(policy: &Policy) -> Result<()> {
    let home = env::var_os("HOME").map(PathBuf::from);

    match policy.mode {
        Mode::Claude => {
            let home = home.ok_or("HOME is not set")?;
            fs::create_dir_all(home.join(".claude"))?;
            // Claude stores config/state in ~/.claude.json. Seed it if missing
            // so a file-level Landlock rule can be applied without opening up
            // the whole home directory.
            let config = home.join(".claude.json");
            if !config.exists() {
                fs::write(&config, "{}\n")?;
            }
        }
        Mode::Opencode => {
            let home = home.ok_or("HOME is not set")?;
            for path in [
                home.join(".opencode"),
                home.join(".local/share/opencode"),
                home.join(".cache/opencode"),
            ] {
                fs::create_dir_all(path)?;
            }
        }
        Mode::Codex => {
            let home = home.ok_or("HOME is not set")?;
            fs::create_dir_all(home.join(".codex"))?;
        }
    }

    Ok(())
}

fn handled_access_mask(abi: i32) -> u64 {
    let mut access = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_REMOVE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_MAKE_CHAR
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_SOCK
        | ACCESS_FS_MAKE_FIFO
        | ACCESS_FS_MAKE_BLOCK
        | ACCESS_FS_MAKE_SYM;

    if abi >= 2 {
        access |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        access |= ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        access |= ACCESS_FS_IOCTL_DEV;
    }

    access
}

fn rw_access_mask(abi: i32) -> u64 {
    let mut access = handled_access_mask(abi);
    if abi < 2 {
        access &= !ACCESS_FS_REFER;
    }
    access
}

fn landlock_abi_version() -> Result<i32> {
    let version = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        ) as i32
    };

    if version < 0 {
        return Err(last_os_error(
            "Landlock is not available (kernel 5.13+ with Landlock enabled required)",
        ));
    }

    Ok(version)
}

fn add_path_rule(ruleset_fd: i32, path: &Path, allowed_access: u64) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_os_error(&format!(
            "failed to open path for Landlock rule: {}",
            path.display()
        )));
    }

    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: fd,
    };

    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr,
            0,
        ) as i32
    };

    let saved = std::io::Error::last_os_error();
    unsafe {
        libc::close(fd);
    }

    if rc != 0 {
        return Err(format!(
            "failed to add Landlock rule for {}: {saved}",
            path.display()
        )
        .into());
    }

    Ok(())
}

fn last_os_error(prefix: &str) -> Box<dyn std::error::Error> {
    format!("{prefix}: {}", std::io::Error::last_os_error()).into()
}
