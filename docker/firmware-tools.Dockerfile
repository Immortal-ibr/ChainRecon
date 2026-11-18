# Build once with: docker build -f docker/firmware-tools.Dockerfile -t chainrecon/firmware-tools:2.0 .
# The runtime uses --network none, a read-only root filesystem, and limits.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       binwalk squashfs-tools qemu-user-static file ca-certificates \
    && mkdir -p /input /output \
    && rm -rf /var/lib/apt/lists/*

ENV HOME=/tmp
USER 65534:65534
WORKDIR /tmp
