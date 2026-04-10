# ============================================================
# W9 DB Server - Multi-stage Docker build
# ============================================================

# Stage 1: Build the Rust server
FROM rust:1.83-slim AS server-builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml ./
COPY server/Cargo.toml ./server/
COPY client/Cargo.toml ./client/

# Create placeholder files for caching
RUN mkdir server/src && echo "fn main() {}" > server/src/main.rs
RUN mkdir client/src && echo "" > client/src/lib.rs

# Fetch dependencies (cached layer)
RUN cargo fetch || true
RUN cd server && cargo fetch || true

# Copy actual source
COPY server/src ./server/src
COPY client/src ./client/src

# Build server
RUN cd server && cargo build --release && cp target/release/w9-db-server /app/w9-db-server

# Stage 2: Runtime image
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash w9db

WORKDIR /app

COPY --from=server-builder /app/w9-db-server /usr/local/bin/w9-db-server

RUN mkdir -p /app/data && chown -R w9db:w9db /app

USER w9db

EXPOSE 8082

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8082/api/health || exit 1

ENV HOST=0.0.0.0
ENV PORT=8082

CMD ["w9-db-server"]
