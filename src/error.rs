use thiserror::Error;

/// Errors that can occur when working with `rzfile` resources.
///
/// Used across parsing, decoding, and validation logic.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum RZError {
    /// No hash was provided where one was required.
    #[error("No hash was provided")]
    NoHashProvided,

    /// A depth value was out of the allowed range or invalid.
    #[error("Invalid depth value")]
    InvalidDepth,

    /// An invalid character was encountered in the input data.
    #[error("Invalid character in input")]
    InvalidCharacter,

    /// The input buffer or structure had an invalid length.
    #[error("Invalid buffer or data length")]
    InvalidLength,

    /// An unspecified or fallback error occurred.
    #[error("Unknown error")]
    Unknown,
}
