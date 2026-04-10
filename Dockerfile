FROM rust:1.83-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY server/Cargo.toml ./server/
COPY client/Cargo.toml ./client/
RUN mkdir -p server/src client/src
RUN echo "fn main(){}" > server/src/main.rs && echo "" > client/src/lib.rs
RUN cargo build --release -p w9-db-server 2>/dev/null || true
COPY server/src ./server/src
COPY client/src ./client/src
RUN cargo build --release -p w9-db-server && cp target/release/w9-db-server /app/server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash appuser
COPY --from=builder /app/server /usr/local/bin/appserver
USER appuser
EXPOSE 8082
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD wget --quiet --tries=1 --spider http://localhost:8082/api/health || exit 1
CMD ["appserver"]
