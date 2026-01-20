# gpg-inspector

A terminal user interface for inspecting GPG/OpenPGP packet structures. Decode armored GPG data and visualize the underlying packet format with color-coded byte highlighting.

Inspired by [ConradIrwin/gpg-decoder](https://github.com/ConradIrwin/gpg-decoder).

## Features

- Interactive TUI with synchronized hex view and packet display
- Real-time parsing as you type or paste armored GPG data
- Color-coded byte visualization linking fields to raw bytes
- Support for both old (3.x) and new (4.x) OpenPGP packet formats
- CRC24 checksum validation for armored input

## Installation

### From source

```bash
git clone https://github.com/jhheider/gpg-inspector
cd gpg-inspector
cargo build --release
```

The binary will be at `target/release/gpg-inspector`.

### Running directly

```bash
cargo run --release
```

## Usage

```bash
# Start with empty input
gpg-inspector

# Load from file
gpg-inspector -f key.asc

# Pipe from GPG
gpg --export --armor KEY_ID | gpg-inspector

# Pipe from file
cat message.asc | gpg-inspector
```

### Options

| Option | Description |
|--------|-------------|
| `-f`, `--file FILE` | Load GPG data from a file |
| `--version` | Show version |
| `--help` | Show help |

## Keyboard Controls

### Global

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch between Input and Data panels |
| `Ctrl+C` / `Ctrl+Q` | Quit |
| `Esc` | Quit |

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

Selecting a field in the Data panel highlights the corresponding bytes in the hex view.

## Supported Packet Types

- Public Key / Public Subkey
- Secret Key / Secret Subkey
- User ID
- Signature (v3, v4)
- Public Key Encrypted Session Key (PKESK)
- Symmetrically Encrypted Integrity Protected Data (SEIPD)

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
