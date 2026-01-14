# 1. Build Stage
# CHANGED: Use 'latest' to ensure we have Rust 1.88+ required by dependencies
FROM rust:latest AS builder

# Set up project directory
WORKDIR /app
COPY . .

# Build the release binary
# This handles the dependencies automatically
RUN cargo build --release

# 2. Runtime Stage
FROM debian:bookworm-slim

# Install certificates for HTTPS (Required for Flashbots/RPC)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary named 'apex_omega' from the builder
COPY --from=builder /app/target/release/apex_omega /app/apex_omega

# Run the binary
CMD ["./apex_omega"]
