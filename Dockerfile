# Latebra node image (T22 ops).
#
#   docker build -t latebra .
#   docker run -p 4040:4040 -p 4090:4090 -v latebra-data:/data latebra \
#     --mine --data /data/chain.db --listen 0.0.0.0:4040 --metrics 0.0.0.0:4090
#
# The default PoW is BLAKE3 (pure Rust), so no C/C++ toolchain is needed; add
# cmake + clang and `--features randomx` for ASIC-resistant RandomX builds.

FROM rust:1-slim AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p latebrad -p lat-explorer -p lat-wallet-cli -p lat-wallet-web

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/latebrad      /usr/local/bin/
COPY --from=builder /src/target/release/lat-explorer  /usr/local/bin/
COPY --from=builder /src/target/release/lat-wallet-cli /usr/local/bin/
COPY --from=builder /src/target/release/lat-wallet-web /usr/local/bin/
VOLUME /data
# P2P + RPC / HTTP metrics
EXPOSE 4040 4090
ENTRYPOINT ["latebrad"]
CMD ["--data", "/data/chain.db", "--listen", "0.0.0.0:4040", "--metrics", "0.0.0.0:4090"]
