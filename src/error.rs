use thiserror::Error;

#[derive(Error, Debug)]
pub enum RZError {
    #[error("No hash has been provided")]
    NoHashProvided,
    #[error("Invalid depth")]
    InvalidDepth,
    #[error("Invalid character")]
    InvalidCharacter,
    #[error("Invalid length")]
    InvalidLength,
    #[error("unknown data store error")]
    Unknown,
}
