//! MiMC preimage statement shared by every proof system.

use crate::MimcParams;

/// Knowledge of `x` such that `E(x) + x = h`. `preimage` is `None` during setup.
#[derive(Clone, Debug)]
pub struct Statement<F> {
    pub params: MimcParams<F>,
    pub hash: F,
    pub preimage: Option<F>,
}
