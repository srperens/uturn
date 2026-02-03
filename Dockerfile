# Build stage
FROM rust:1.84-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/release/uturn /usr/local/bin/uturn

# Default port
EXPOSE 3478/udp

# Required: UTURN_EXTERNAL_IP must be set
# Optional: UTURN_PORT, UTURN_REALM, UTURN_USERS, UTURN_LOG_LEVEL

ENTRYPOINT ["/usr/local/bin/uturn"]
