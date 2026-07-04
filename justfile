# Development recipes; CI runs the same checks (.github/workflows)

# Run all checks: formatting, linting, tests
check: fmt clippy test

# Check formatting
fmt:
    cargo fmt --all -- --check

# Run the linter over every target, matching CI
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run all tests
test:
    cargo test --workspace --all-features

# Build the release binary
build:
    cargo build --release

# Coverage via tarpaulin (uses Docker on macOS: tarpaulin is Linux-only)
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname)" == "Darwin" ]]; then
        docker run --rm -v "$PWD:/volume" -w /volume \
            xd009642/tarpaulin cargo tarpaulin
    else
        cargo tarpaulin
    fi

# Security audit (also runs weekly in CI)
audit:
    cargo audit
