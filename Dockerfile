# DiscoMCP as an MCP server over stdio.
# Uses the prebuilt release binary so the image builds in seconds (no Rust
# toolchain, no long compile) — introspection-ready for hosted indexers.
# Build: docker build -t discomcp .
# Run:   docker run -i --rm discomcp        # newline-delimited JSON-RPC on stdio
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*
ARG VERSION=v0.5.1
RUN curl -fsSL "https://github.com/ieranama/discomcp/releases/download/${VERSION}/discomcp-x86_64-unknown-linux-gnu.tar.xz" \
      -o /tmp/discomcp.tar.xz \
    && tar -xJf /tmp/discomcp.tar.xz -C /tmp \
    && install -m 0755 /tmp/discomcp-x86_64-unknown-linux-gnu/discomcp /usr/local/bin/discomcp \
    && rm -rf /tmp/discomcp*
# `serve` responds to initialize + tools/list with no config.
ENTRYPOINT ["discomcp", "serve"]
