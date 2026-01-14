# 1. Build Stage
FROM rust:1.84-bookworm as builder

WORKDIR /app
COPY . .

# This creates the binary at: /app/target/release/apex_omega
RUN cargo build --release

# 2. Runtime Stage
FROM debian:bookworm-slim

# Install SSL certificates (Required for HTTPS/RPC)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# COPY: Takes 'apex_omega' from builder and puts it in runtime folder
COPY --from=builder /app/target/release/apex_omega /app/apex_omega

# RUN: Executes the binary
CMD ["./apex_omega"]
