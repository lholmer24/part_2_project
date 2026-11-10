//! The MiMC preimage statement shared by every proof system.

use crate::MimcParams;

/// One MiMC preimage statement.
///
/// The statement is knowledge of `x` such that `E(x) + x = h`. The same value
/// is used by every system; only the circuit encoding differs.
#[derive(Clone, Debug)]
pub struct Statement<F> {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<F>,
    /// Public hash, h.
    pub hash: F,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<F>,
}
