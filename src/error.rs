use std::fmt::Display;

#[derive(Debug, PartialEq, Eq)]
pub enum RZError {
    NoHashProvided,
    InvalidDepth,
    InvalidCharacter,
    InvalidLength,
    Unknown,
}

impl Display for RZError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::InvalidCharacter => write!(f, "Invalid character!"),
            Self::InvalidDepth => write!(f, "Invalid depth!"),
            Self::InvalidLength => write!(f, "Invalid length!"),
            Self::NoHashProvided => write!(f, "No hash has been provided!"),
            Self::Unknown => write!(f, "Unknown error occured!"),
        }
    }
}
