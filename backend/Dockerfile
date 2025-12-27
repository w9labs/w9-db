FROM rust:1.83-alpine as builder
WORKDIR /usr/src/app
RUN apk add --no-cache musl-dev openssl-dev pkgconfig
COPY . .
RUN cargo install --path .

FROM alpine:3.19
RUN apk add --no-cache libgcc
COPY --from=builder /usr/local/cargo/bin/w9-db /usr/local/bin/w9-db
CMD ["w9-db"]
