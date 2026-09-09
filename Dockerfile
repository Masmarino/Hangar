FROM node:26-alpine3.24 AS frontend-build

WORKDIR /app/frontend

COPY frontend/package*.json ./

RUN npm ci

COPY frontend/ ./

RUN npm run build -- --configuration production

FROM rust:1.98.0-alpine3.24 AS chef

WORKDIR /app

RUN apk add --no-cache pkgconfig build-base perl

COPY rust-toolchain.toml ./
RUN cargo install cargo-chef --version 0.1.78 --locked

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS backend-build

COPY --from=planner /app/recipe.json recipe.json

ENV SQLX_OFFLINE=true

RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY .sqlx ./.sqlx

RUN cargo build --release -p hangar-api --locked

FROM alpine:3.24 AS runtime

WORKDIR /app

ARG TARGETARCH
ARG TRIVY_VERSION=0.74.0

RUN apk add --no-cache ca-certificates curl \
    && TRIVY_ARCH=$(if [ "$TARGETARCH" = "arm64" ]; then echo ARM64; else echo 64bit; fi) \
    && TRIVY_TARBALL="trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    && curl -sfL -o "/tmp/${TRIVY_TARBALL}" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_TARBALL}" \
    && curl -sfL -o /tmp/trivy_checksums.txt "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" \
    && (cd /tmp && grep " ${TRIVY_TARBALL}\$" trivy_checksums.txt | sha256sum -c -) \
    && tar -xzf "/tmp/${TRIVY_TARBALL}" -C /usr/local/bin trivy \
    && rm "/tmp/${TRIVY_TARBALL}" /tmp/trivy_checksums.txt \
    && apk del curl

COPY --from=backend-build /app/target/release/hangar-api ./hangar-api
COPY --from=frontend-build /app/frontend/dist/hangar-web/browser ./static

ENV STATIC_DIR=/app/static

EXPOSE 8080

RUN addgroup -S hangar && adduser -S -G hangar -h /app -H hangar \
    && mkdir -p /data \
    && chown -R hangar:hangar /app /data

USER hangar

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1

CMD ["./hangar-api"]
