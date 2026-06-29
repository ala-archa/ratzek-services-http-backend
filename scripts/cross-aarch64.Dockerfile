# Cross-compile the aarch64 release binary on an x86_64 host, with a glibc that
# matches production (Raspberry Pi / Debian 11 = glibc 2.31). The whole Rust +
# C cross toolchain lives inside the image, so the host needs only Docker
# (no rustup — which can't run on Guix anyway).
#
# Build the image once:
#   docker build -t ratzek-cross-aarch64 -f scripts/cross-aarch64.Dockerfile scripts
# Then see scripts/deploy.sh for the build+ship flow.
FROM rust:1-bullseye

RUN dpkg --add-architecture arm64 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      pkg-config libssl-dev:arm64 \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add aarch64-unknown-linux-gnu

# rusqlite `bundled` compiles SQLite from C — point the cc crate + linker at the
# aarch64 cross toolchain. openssl-sys (via reqwest's native-tls) links the arm64
# OpenSSL installed above; pkg-config must read the arm64 .pc files and allow
# cross. Same OpenSSL 1.1.1 (Debian 11) as the Pi, so the binary is unchanged.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    PKG_CONFIG_ALLOW_CROSS=1 \
    PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig

WORKDIR /src
