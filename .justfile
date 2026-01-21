tarpaulin := "cargo tarpaulin --config tarpaulin.toml --all-features"

# Show all tasks
[private]
default:
  just -l

# Run all checks (fmt, clippy, test)
check: fmt clippy test

# Check formatting
fmt:
  cargo fmt --all -- --check

# Run clippy
clippy:
  cargo clippy --all-features -- -D warnings

# Run tests
test:
  cargo test --workspace --all-features

# Generate coverage report (requires cargo-tarpaulin, uses docker on macOS)
coverage:
  #!/usr/bin/env bash
  if [[ "$(uname -s)" == "Darwin" ]]; then
    just docker-coverage
  else
    mkdir -p coverage
    {{tarpaulin}}
  fi

# Run coverage in docker (for macOS ptrace issues)
docker-coverage:
  docker run \
    --rm \
    --pull always \
    --volume .:/volume \
    --workdir /volume \
    --security-opt seccomp=unconfined \
    xd009642/tarpaulin \
    {{tarpaulin}}

# Build release
build:
  cargo build --release

# Clean build artifacts
clean:
  cargo clean
  rm -rf coverage
