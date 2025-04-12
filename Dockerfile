# ---- Build Stage ----
FROM rust:1.77-slim as builder

WORKDIR /app

# 依存関係キャッシュのため、Cargo.tomlとCargo.lockのみを先にコピー
COPY Cargo.toml Cargo.lock ./
RUN mkdir src
RUN echo "fn main() {}" > src/main.rs
RUN cargo build --release || true

# ソースコードをコピーして本ビルド
COPY . .
RUN cargo build --release

# ---- Runtime Stage ----
FROM debian:bullseye-slim

# 必要なライブラリのみインストール（libssl等が必要な場合がある）
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# builderからバイナリのみコピー
COPY --from=builder /app/target/release/vulnhuntrs /app/vulnhuntrs

# 非rootユーザー作成
RUN useradd -m appuser
USER appuser

ENTRYPOINT ["./vulnhuntrs"]
