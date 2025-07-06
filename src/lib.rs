#![warn(missing_docs)]
//! # rzfile
//! A library for handling client files used by the RZEmulator project.
//!
//! This crate provides tools to parse, decrypt and interpret game resource files
//! such as `data.000` and associated hashed archives.

/// Contains the [`RZError`] type returned by various operations in this crate.
pub mod error;

/// Functions related to parsing and handling the `data.00x` archive files,
/// including parsing index data and resolving offsets.
pub mod file;

/// Provides encryption and decryption utilities for file content and hashed file names.
pub mod name;
