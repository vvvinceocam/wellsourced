FROM rust:trixie AS build

WORKDIR /app

COPY Cargo.toml Cargo.lock /app/
COPY src /app/src

RUN cargo build --release

#============================================================================

FROM debian:trixie

COPY --from=build /app/target/release/wellsourced /usr/local/bin/wellsourced

ENV PATH="/usr/local/bin:$PATH"
