#![warn(missing_docs)]
//! # rzfile
//! A library for handling client files

/// Contains the errors returned by this library
mod error;
/// Contains file functions related to the data.00x files.
pub mod file;
/// Contains all the functions related to encryption and decryption of file names.
pub mod name;
