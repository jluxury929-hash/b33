# 1. Build Stage
FROM rust:latest AS builder

WORKDIR /app
COPY . .

# Build release (auto-detects main.rs in root via Cargo.toml [[bin]])
RUN cargo build --release

# 2. Runtime Stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/apex_omega /app/apex_omega
CMD ["./apex_omega"]
