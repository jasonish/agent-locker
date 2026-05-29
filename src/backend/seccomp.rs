//! A minimal seccomp-BPF filter that blocks the `TIOCSTI` ioctl.
//!
//! `TIOCSTI` pushes bytes into a terminal's input queue. A sandboxed agent
//! holding a writable fd to its controlling terminal (its inherited stdin, or
//! `/dev/tty`) can use it to inject a command line that the *parent* shell runs
//! after agent-locker exits — outside the sandbox. Landlock cannot prevent this:
//! its `ACCESS_FS_IOCTL_DEV` right is all-or-nothing (denying it would also
//! break the termios/window-size ioctls a TUI needs), and the terminal fds are
//! inherited from before the sandbox, so Landlock never mediates them anyway.
//!
//! Unlike a namespace sandbox such as bubblewrap, we cannot detach the
//! controlling terminal with `setsid()` — the interactive agent needs it for
//! `SIGWINCH`/`SIGINT` delivery and raw mode. So we filter the single offending
//! ioctl command instead, leaving every other ioctl untouched.
//!
//! The filter is installed once, just before `landlock_restrict_self`, and is
//! preserved across `execve`, so it also covers everything the agent spawns.
//! It requires `PR_SET_NO_NEW_PRIVS`, which the caller sets first.

use crate::Result;

// Classic BPF instruction classes/fields, from <linux/bpf_common.h>.
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

// seccomp return actions, from <linux/seccomp.h>.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

// AUDIT_ARCH_X86_64, from <linux/audit.h>. The crate is x86_64-only (enforced
// in the Landlock backend), but the filter still checks the architecture so a
// mismatch fails open rather than misinterpreting an unrelated syscall number.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// TIOCSTI, from <asm-generic/ioctls.h>.
const TIOCSTI: u32 = 0x5412;

// Byte offsets into `struct seccomp_data { int nr; u32 arch; u64 ip; u64 args[6]; }`.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
// Low 32 bits of args[1] on little-endian. `ioctl(2)`'s request is an `unsigned
// long`, but the kernel acts only on the low bits that encode the command, so
// matching the low word is what mirrors the kernel's own dispatch. Classic BPF
// can't load all 64 bits in one step; checking just this word can at worst
// over-match (a request sharing the low word), never let a real TIOCSTI slip.
const OFFSET_ARG1: u32 = 24;

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Installs a seccomp filter that makes `ioctl(_, TIOCSTI, _)` fail with
/// `EPERM` while allowing every other syscall (and every other ioctl) through.
///
/// Must be called after `PR_SET_NO_NEW_PRIVS` is set; the filter is inherited
/// across `execve`.
pub fn install_tiocsti_block() -> Result<()> {
    // jt/jf are instruction counts relative to the slot *after* the jump.
    // Each "not equal" branch jumps to the trailing ALLOW (index 7).
    let filter = [
        // A = seccomp_data.arch
        stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        // if A != x86_64 -> ALLOW (fail open on a foreign arch)
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 5),
        // A = seccomp_data.nr
        stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        // if A != ioctl -> ALLOW
        jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_ioctl as u32, 0, 3),
        // A = request (low word of args[1])
        stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARG1),
        // if A != TIOCSTI -> ALLOW
        jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 0, 1),
        // deny with EPERM
        stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32 & SECCOMP_RET_DATA),
        ),
        // allow
        stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    ];

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // seccomp(2) (Linux 3.17+) rather than prctl, to avoid the variadic ABI.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &prog as *const SockFprog,
        )
    };
    if rc != 0 {
        return Err(format!(
            "failed to install seccomp TIOCSTI filter: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Installs the filter in a forked child and checks that `TIOCSTI` is
    /// rejected with `EPERM` while an unrelated ioctl still reaches the kernel.
    /// Done in a child because a seccomp filter cannot be removed and would
    /// otherwise outlive the test in the shared test-runner process. The child
    /// uses only async-signal-safe libc calls and `_exit`.
    #[test]
    fn blocks_tiocsti_but_allows_other_ioctls() {
        unsafe {
            let mut fds = [0i32; 2];
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0, "pipe failed");

            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");

            if pid == 0 {
                // Child: arm NO_NEW_PRIVS, install the filter, probe ioctls.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(10);
                }
                if install_tiocsti_block().is_err() {
                    libc::_exit(11);
                }

                // TIOCSTI must be denied by the filter (EPERM) before the
                // kernel ioctl handler runs — not ENOTTY from the non-tty fd.
                let ch: u8 = b'x';
                let r = libc::ioctl(fds[0], TIOCSTI as _, &ch as *const u8);
                if r != -1 || *libc::__errno_location() != libc::EPERM {
                    libc::_exit(12);
                }

                // A non-filtered ioctl must still work (FIONREAD on a pipe).
                let mut navail: libc::c_int = -1;
                if libc::ioctl(fds[0], libc::FIONREAD as _, &mut navail) != 0 {
                    libc::_exit(13);
                }

                libc::_exit(0);
            }

            // Parent.
            libc::close(fds[0]);
            libc::close(fds[1]);
            let mut status = 0i32;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid, "waitpid failed");
            assert!(libc::WIFEXITED(status), "child did not exit normally");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "child failed at stage {}",
                libc::WEXITSTATUS(status)
            );
        }
    }
}
