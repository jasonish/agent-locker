mod landlock;
mod seccomp;

use crate::Result;
use crate::policy::Policy;

pub fn exec(policy: &Policy) -> Result<()> {
    landlock::exec(policy)
}
