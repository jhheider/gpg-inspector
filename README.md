[![Coverage Status](https://coveralls.io/repos/github/jhheider/gpg-inspector/badge.svg?branch=main)](https://coveralls.io/github/jhheider/gpg-inspector?branch=main)
[![Test Status](https://github.com/jhheider/gpg-inspector/actions/workflows/test.yml/badge.svg)](https://github.com/jhheider/gpg-inspector/actions/workflows/test.yml)
[![Checks](https://github.com/jhheider/gpg-inspector/actions/workflows/check-and-lint.yaml/badge.svg)](https://github.com/jhheider/gpg-inspector/actions/workflows/check-and-lint.yaml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# gpg-inspector

A terminal user interface for inspecting GPG/OpenPGP packet structures. Decode armored GPG data and visualize the underlying packet format with color-coded byte highlighting.

Inspired by [ConradIrwin/gpg-decoder](https://github.com/ConradIrwin/gpg-decoder).

## Features

- Interactive TUI with synchronized hex view and packet display
- Real-time parsing as you type or paste armored GPG data
- Raw binary input: open unarmored `.gpg`/`.sig` files or pipe binary data
- Computed key fingerprints and key IDs (SHA-1 for v4, SHA-256 for v6 keys)
- Compressed Data packets are decompressed (ZIP/ZLIB/BZip2) and their nested packets parsed
- Multiple armor blocks in one input, and cleartext signed messages
- Color-coded byte visualization linking fields to raw bytes
- Field search (`/`), full-value detail view (`Enter`), and collapsible packets (`Space`)
- Focusable hex panel with byte cursor and reverse lookup (jump to the field owning a byte)
- Copy field values or raw bytes to the clipboard via OSC 52 (`y` / `Y`)
- Mouse support: click to focus/select, wheel to scroll
- Dark and light themes (`--theme auto|dark|light`, auto-detected from `COLORFGBG`)
- Old and new OpenPGP packet formats: v4/v6 keys, v3/v4/v6 signatures (RFC 4880 and RFC 9580)
- Scriptable text and JSON output modes (`--txt`, `--json`)
- CRC24 checksum validation for armored input

## Installation

### Prebuilt binaries

Download the latest release for your platform from the
[releases page](https://github.com/jhheider/gpg-inspector/releases):

| Platform | Download |
|----------|---------|
| Linux x86_64 | `gpg-inspector-linux-x86_64.tar.gz` |
| Linux aarch64 | `gpg-inspector-linux-aarch64.tar.gz` |
| macOS x86_64 | `gpg-inspector-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `gpg-inspector-macos-aarch64.tar.gz` |
| Windows x86_64 | `gpg-inspector-windows-x86_64.zip` |

```bash
# Linux / macOS
tar xzf gpg-inspector-*.tar.gz
sudo mv gpg-inspector /usr/local/bin/
```

### From source

```bash
git clone https://github.com/jhheider/gpg-inspector
cd gpg-inspector
cargo build --release
# binary at target/release/gpg-inspector
```

## Usage

```bash
# Start with empty input
gpg-inspector

# Load from file (armored or raw binary)
gpg-inspector -f key.asc
gpg-inspector -f key.gpg

# Pipe from GPG (armored or binary)
gpg --export --armor KEY_ID | gpg-inspector
gpg --export KEY_ID | gpg-inspector

# Pipe from file
cat message.asc | gpg-inspector

# Non-interactive output for scripting
gpg-inspector -f key.asc --json | jq '.packets[].tag'
gpg-inspector -f key.asc --txt
```

### Options

| Option | Description |
|--------|-------------|
| `-f`, `--file FILE` | Load GPG data from a file |
| `--txt` | Print parsed packets as formatted text (with hex dump) and exit |
| `--json` | Print parsed packets as JSON and exit |
| `--theme THEME` | TUI color theme: `auto` (default), `dark`, or `light` |
| `--version` | Show version |
| `--help` | Show help |

`--json` is available in the default build. If you build with
`--no-default-features` (minimal TUI-only binary), re-enable it with
`--features serde`.

## Keyboard Controls

### Global

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Cycle focus: Input, Hex, Data |
| `F1` | Toggle help overlay |
| `Ctrl+C` / `Ctrl+Q` | Quit |
| Mouse | Click to focus/select, wheel to scroll (Shift+drag for native selection) |

### Input Panel

| Key | Action |
|-----|--------|
| `Backspace` | Delete character before cursor |
| `Delete` | Delete character at cursor |
| `Left` / `Right` | Move cursor |
| `Home` / `End` | Move to start/end of input |
| `Enter` | Add newline |
| `Ctrl+A` | Move cursor to start |
| `Ctrl+E` | Move cursor to end |
| `Ctrl+K` | Clear input |

### Data Panel

| Key | Action |
|-----|--------|
| `Up` / `k` | Move selection up |
| `Down` / `j` | Move selection down |
| `Page Up` / `Page Down` | Move selection by page |
| `Home` / `End` | Jump to first/last field |
| `Enter` | Show full details for the selected field |
| `Space` | Fold / unfold the selected packet (`h` collapse, `l` expand) |
| `/` | Search fields by name or value (`Enter` jumps, `Esc` cancels; jumps auto-expand folds) |
| `n` / `N` | Jump to next / previous search match |
| `y` / `Y` | Copy field value / raw bytes as hex to the clipboard (OSC 52) |
| `?` | Toggle help overlay |

### Hex Panel

| Key | Action |
|-----|--------|
| `h`/`l`/`j`/`k` or arrows | Move the byte cursor (left/right/line down/up) |
| `Page Up` / `Page Down` | Move by page |
| `g` / `G`, `Home` / `End` | Jump to first / last byte |
| `Enter` or `f` | Select the field owning the byte under the cursor |

Selecting a field in the Data panel highlights the corresponding bytes in the hex view. For nested (decompressed) packets, the hex view switches to the decompressed buffer.

## Supported Packet Types

Every exportable packet type defined by RFC 4880 and RFC 9580 is parsed (see
[RFC4880_COMPLIANCE.md](RFC4880_COMPLIANCE.md) and
[RFC9580_COMPLIANCE.md](RFC9580_COMPLIANCE.md) for the full compliance tables):

- Public Key / Public Subkey and Secret Key / Secret Subkey (v3–v6)
- Signature (v3, v4, v6) with all subpacket types
- One-Pass Signature
- Public Key Encrypted Session Key (PKESK)
- Symmetric-Key Encrypted Session Key (SKESK)
- Symmetrically Encrypted Data (legacy) and SEIPD v1/v2
- AEAD Encrypted Data and Padding (RFC 9580)
- Literal Data, Compressed Data, Marker
- User ID and User Attribute
- Modification Detection Code (MDC)
- Private/Experimental (tags 60–63)

Trust packets (tag 12) are intentionally not parsed—they are
implementation-specific and never exported.

### Supported Algorithms

- RSA
- DSA
- ElGamal
- ECDSA / ECDH
- EdDSA
- X25519 / Ed25519

## Project Structure

```
gpg-inspector/
├── gpg-inspector/        # TUI application
│   └── src/
│       ├── main.rs       # Entry point, CLI
│       ├── app.rs        # Application state
│       ├── event.rs      # Input handling
│       └── ui/           # Terminal rendering
└── gpg-inspector-lib/    # Parsing library
    └── src/
        ├── armor.rs      # ASCII armor decoding
        ├── stream.rs     # Byte stream abstraction
        └── packet/       # OpenPGP packet parsers
```

## Building and Testing

```bash
# Build
cargo build

# Run tests
cargo test

# Run with coverage (requires cargo-llvm-cov)
cargo llvm-cov

# Format check
cargo fmt --check

# Lint
cargo clippy
```

## Requirements

- Rust 1.85+ (edition 2024)
- Terminal with color support

## License

MIT License. See [LICENSE](LICENSE) for details.
