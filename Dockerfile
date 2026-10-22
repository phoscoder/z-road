# syntax=docker/dockerfile:1
#
# One image with every Z-Road binary; docker-compose.yml starts each service with its
# own command. Build:  docker build -t zroad:local .
#
# NOTE: written without access to a Docker daemon. The Dockerfile and the compose file
# are exercised by .github/workflows/docker.yml; the bootstrap script and the commands
# they run are exercised natively by deploy/smoke-host.sh.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY examples examples
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
      -p central-server -p timestamp-service -p security-server -p signer-service \
      -p zroad-cli -p zimra-clearance -p buyer-client -p citizen-portal \
 && mkdir /out \
 && for b in central-server timestamp-service security-server signer-service \
             zroad-cli zimra-clearance buyer-client citizen-portal; do \
      cp "target/release/$b" /out/; \
    done

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin zroad \
 && mkdir /data && chown 10001:10001 /data
COPY --from=build /out/ /usr/local/bin/
COPY deploy/bootstrap.sh /usr/local/bin/zroad-bootstrap
COPY examples/zimra-clearance/schemas /usr/local/share/zroad/schemas
USER 10001:10001
WORKDIR /data
VOLUME /data
# Every service runs as its own process in its own container; there is no default command.
CMD ["zroad-cli", "--help"]
