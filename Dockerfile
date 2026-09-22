# syntax=docker/dockerfile:1.7
# Build tooling only: customer hosts download the resulting executable.
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder
ENV CARGO_BUILD_JOBS=2
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY modules ./modules
COPY distribution ./distribution
RUN cargo build --locked --release --bin thelve

FROM scratch AS binary
COPY --from=builder /source/target/release/thelve /thelve
