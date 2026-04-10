# ============================================================
# Stage 1: Build Leptos WASM client
# ============================================================
FROM rust:1.94-slim AS wasm-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
RUN cargo install --locked trunk
COPY Cargo.toml ./
COPY client/Cargo.toml ./client/
COPY client/src/ ./client/src/
COPY client/Trunk.toml ./client/
COPY client/index.html ./client/
RUN cd client && trunk build --release --dist /app/site/pkg 2>&1 | tail -5

# ============================================================
# Stage 2: Build Rust server
# ============================================================
FROM rust:1.94-slim AS server-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
COPY server/Cargo.toml ./server/
COPY client/Cargo.toml ./client/
RUN mkdir -p server/src client/src
RUN echo "fn main(){}" > server/src/main.rs && echo "" > client/src/lib.rs
RUN cargo build --release -p w9-db-server 2>/dev/null || true
COPY server/src ./server/src
RUN cargo build --release -p w9-db-server && cp target/release/w9-db-server /app/server

# ============================================================
# Stage 3: Runtime image
# ============================================================
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash appuser
COPY --from=server-builder /app/server /usr/local/bin/appserver
COPY --from=wasm-builder /app/site/pkg /app/site/pkg
WORKDIR /app
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD wget --quiet --tries=1 --spider http://localhost:8080/api/health || exit 1
CMD ["/usr/local/bin/appserver"]
