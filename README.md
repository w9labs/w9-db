# W9 Database - OAuth Provider

Central OAuth 2.0 / OpenID Connect provider for all W9 services.

## Tech Stack

- **Backend**: Rust + Axum + SurrealDB
- **Frontend**: Leptos (Full-stack SSR)
- **Authentication**: OAuth 2.0 / OIDC compliant
- **Password Hashing**: Argon2
- **Tokens**: JWT with configurable expiration

## Features

- OAuth 2.0 Authorization Code Flow
- OpenID Connect Discovery
- Role-based access control (Admin, Dev, User)
- API token management
- User registration with verification
- Password reset flow
- SurrealDB backend (supports in-memory or RocksDB persistence)

## Quick Start

### Development

```bash
# Copy environment file
cp .env.example .env

# Run with cargo
cargo run --package w9-db-server
```

### Docker

```bash
# Build
docker build -t w9-db .

# Run
docker run -p 8082:8082 \
  -e JWT_SECRET=your-secret \
  -e DEFAULT_ADMIN_EMAIL=admin@w9.nu \
  -e DEFAULT_ADMIN_PASSWORD=your-secure-password \
  w9-db
```

### Docker Compose

```bash
docker-compose up -d
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | SurrealDB connection | `memory` |
| `JWT_SECRET` | JWT signing secret | (required) |
| `ISSUER_URL` | OIDC issuer URL | `https://db.w9.nu` |
| `DEFAULT_ADMIN_EMAIL` | Default admin email | `admin@w9.nu` |
| `DEFAULT_ADMIN_PASSWORD` | Default admin password | (required) |
| `PORT` | Server port | `8082` |

## API Endpoints

### Health
- `GET /api/health` - Health check

### OAuth 2.0 / OIDC
- `GET /.well-known/openid-configuration` - OIDC Discovery
- `GET /authorize` - OAuth authorization endpoint
- `POST /oauth/token` - OAuth token endpoint
- `GET /userinfo` - OIDC userinfo endpoint

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration

## Deployment

### Dokploy

This project is Dokploy-ready. Use the docker-compose.yml for deployment:

```yaml
version: '3.8'
services:
  w9-db:
    image: ghcr.io/w9labs/w9-db:latest
    ports:
      - "8082:8082"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - DATABASE_URL=rocksdb:///app/data/w9-db
    volumes:
      - w9-db-data:/app/data
```

## License

GPL v3.0
