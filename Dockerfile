FROM rust:1.94-slim-bookworm AS server-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev libpq-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY server/Cargo.toml ./server/
COPY server/infra/templates/voxel.css ./server/infra/templates/voxel.css
RUN mkdir -p server/src
RUN echo "fn main(){}" > server/src/main.rs
RUN cargo fetch --locked 2>/dev/null || cargo fetch
COPY server/src ./server/src
RUN cargo build --release -p w9-db-server && cp target/release/w9-db-server /usr/local/bin/appserver

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl libssl3 libpq5 ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash appuser
COPY --from=server-builder /usr/local/bin/appserver /usr/local/bin/appserver
COPY public/w9-logo /app/public/w9-logo
WORKDIR /app
RUN chmod +x /usr/local/bin/appserver
USER appuser
EXPOSE 8082
CMD ["/usr/local/bin/appserver"]
