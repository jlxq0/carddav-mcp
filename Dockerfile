# syntax=docker/dockerfile:1.7

# Multi-stage build -> distroless runtime. carddav-mcp is stateless and uses
# pure-Rust HTTPS/XML dependencies only.
ARG RUST_VERSION=1.93
FROM rust:${RUST_VERSION}-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("dep stub"); }' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/deps/carddav_mcp* target/release/carddav-mcp*

COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:e2d29aec8061843706b7e484c444f78fafb05bfe47745505252b1769a05d14f1

WORKDIR /app
COPY --from=builder /build/target/release/carddav-mcp /app/carddav-mcp

USER nonroot:nonroot

EXPOSE 3000
ENTRYPOINT ["/app/carddav-mcp"]
