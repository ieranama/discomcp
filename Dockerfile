# DiscoMCP as an MCP server over stdio.
# Build: docker build -t discomcp .
# Run:   docker run -i --rm discomcp        # speaks newline-delimited JSON-RPC on stdio
FROM rust:1.82 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin discomcp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/discomcp /usr/local/bin/discomcp
# Introspection-ready: `serve` responds to initialize + tools/list with no config.
ENTRYPOINT ["discomcp", "serve"]
