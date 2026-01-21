# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Run all checks (formatting, linting, tests)
just check

# Individual commands
just fmt          # Check formatting
just clippy       # Run linter
just test         # Run all tests

# Run a single test
cargo test --package gpg-inspector-lib test_name

# Run tests for a specific module
cargo test --package gpg-inspector-lib packets::skesk

# Build release binary
just build        # or: cargo build --release

# Coverage (uses Docker on macOS)
just coverage

# Direct cargo commands
cargo test --workspace --all-features
cargo clippy --all-features -- -D warnings
cargo fmt --all -- --check
```

## Architecture

This is a Rust workspace with two crates:

### gpg-inspector-lib (parsing library)

The library parses OpenPGP packets per RFC 4880/9580. It does NOT perform cryptographic operations—it only extracts and displays packet structure.

**Key modules:**
- `armor.rs` - ASCII armor decoding (Base64 + CRC24)
- `stream.rs` - `ByteStream` abstraction for reading binary data with position tracking
- `packet/mod.rs` - Packet parsing dispatcher and `Field` type for parsed data
- `packet/*.rs` - Individual packet type parsers (one file per packet type)
- `lookup.rs` - Algorithm ID → name lookup tables

**Parsing flow:**
1. `parse()` decodes ASCII armor via `decode_armor()`
2. `parse_packets()` iterates through raw bytes, parsing packet headers
3. `parse_packet_body()` dispatches to type-specific parsers based on packet tag
4. Each parser returns a `PacketBody` enum variant with parsed data

**Field spans:** Every parsed field includes a `(start, end)` byte span into the original data, enabling hex highlighting in the TUI.

### gpg-inspector (TUI application)

A terminal UI built with `ratatui` that displays parsed packets with synchronized hex view.

**Key modules:**
- `app.rs` - Application state, input buffer, parsing
- `event.rs` - Keyboard input handling
- `ui/` - Terminal rendering (panels, colors)
- `output.rs` - Text/JSON output formatting

## Test Organization

Tests in `gpg-inspector-lib/tests/`:
- `packets/` - Unit tests for each packet type using constructed byte sequences
- `integration.rs` - Re-exports packet tests plus integration tests
- `lookup.rs`, `signature.rs`, `public_key.rs` - Additional coverage

**Test pattern:** Most packet tests construct raw bytes programmatically, then parse them and verify fields contain expected values.

## Coverage

The library maintains 100% line coverage. When adding new parsing code, add corresponding tests in `tests/packets/`.
