# Contributing to `rzfile`

Thanks for your interest in contributing to `rzfile`!  
Below you'll find the basic guidelines to help you get started.

---

## Requirements

* **Rust stable** (check with `rustc --version`)
* Use `cargo fmt`, `cargo clippy`, and `cargo test` before submitting any PRs
* Optional: `cargo nextest` and code coverage tools like `cargo tarpaulin`

---

## Running Tests

```bash
cargo test
```

To get code coverage:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

---

## Project Structure

* `src/lib.rs`: Crate root
* `src/file.rs`: File parsing and index handling
* `src/name.rs`: Encoding/decoding logic for filenames
* `src/error.rs`: Error types and descriptions
* `tests/`: Additional integration tests

---

## Code Style

Use:

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
```

No warnings or `unwrap()`s in final PRs unless justified.

---

## Pull Request Checklist

Before opening a PR:

* All tests pass (`cargo test`)
* Code is formatted (`cargo fmt`)
* No Clippy warnings (`cargo clippy`)
* No unnecessary `unwrap()`, `expect()`, or panics
* Added or updated tests if functionality changed
* Relevant documentation updated (including `README.md` or inline rustdoc)

---

## Commit Guidelines

Follow conventional commits:

* `feat: Add ...`
* `fix: Correct ...`
* `test: Add test for ...`
* `chore: Maintenance ...`
* `docs: Update README / comments`

---

## Feedback & Issues

Found a bug or have a feature idea?

* Use [GitHub Issues](https://github.com/NGemity/rzfile/issues)
* Try to reproduce bugs with a minimal test case

---

## License

By contributing, you agree that your code will be licensed under the same license as the rest of the project: MIT.

---

Thanks again,
The `rzfile` Maintainers
