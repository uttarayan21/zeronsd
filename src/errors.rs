pub use error_stack::{Report, ResultExt};
#[derive(Debug, thiserror::Error)]
#[error("An error occurred")]
pub struct Error;

pub type ErrorReport = Report<Error>;
pub type Result<T, E = error_stack::Report<Error>> = core::result::Result<T, E>;
