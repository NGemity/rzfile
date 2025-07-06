<p align="center">
        <img height="100px" src="https://ngemity.dev/logo_white.png" />
</p>

<h2 align="center">rzfile<br>Rust Library for client file handling</h2>
  
  
# rzfile

[![CI](https://github.com/NGemity/rzfile/actions/workflows/ci.yml/badge.svg)](https://github.com/NGemity/rzfile/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/NGemity/rzfile/graph/badge.svg?token=FPK427O7U9)](https://codecov.io/github/NGemity/rzfile)
[![crates.io](https://img.shields.io/crates/v/rzfile.svg)](https://crates.io/crates/rzfile)
[![docs.rs](https://docs.rs/rzfile/badge.svg)](https://docs.rs/rzfile)

`rzfile` is a lightweight Rust library designed for parsing and handling binary file structures used in proprietary MMO game clients. It's part of the [`NGemity`](https://github.com/NGemity) project and supports tools such as the [RZEmulator](https://github.com/NGemity/RZEmulator).

## Features

* Parser for `data.00x` index files
* File name encryption and decryption based on game-specific logic
* Customizable encryption and reference tables
* Precise error handling via `RZError` (compatible with `thiserror`)
* Fully tested with high code coverage
* Minimal dependencies (only `thiserror` optionally)

## Example

```rust
use rzfile::file::parse_index;
use rzfile::name::{encode_file_name, decode_file_name};

let mut buffer = std::fs::read("data.000").unwrap();
let entries = parse_index(&mut buffer, None).unwrap();

let encoded = encode_file_name("test.dds", None, None).unwrap();
let decoded = decode_file_name(&encoded, None, None, true).unwrap();

assert_eq!(decoded, "test.dds");
```

## Installation

```bash
cargo add rzfile
```

Or manually via `Cargo.toml`:

```toml
[dependencies]
rzfile = "0.1"
```

## Documentation

* [docs.rs/rzfile](https://docs.rs/rzfile)
* [crates.io/crates/rzfile](https://crates.io/crates/rzfile)

## License

MIT © [NGemity](https://github.com/NGemity)
