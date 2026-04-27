FROM nvidia/cuda:12.8.1-devel-ubuntu24.04 AS builder

# System build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    cmake \
    clang \
    libclang-dev \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
# Toolchains: stable for cargo-openvm, nightly for tco build
ENV CARGO_HOME="/root/.cargo" \
    RUSTUP_HOME="/root/.rustup" \
    PATH="/root/.cargo/bin:${PATH}"
RUN rustup toolchain install nightly-2026-01-01 \
    && rustup component add rust-src --toolchain nightly-2026-01-01

# Install cargo-openvm (builds the guest ELF)
RUN cargo +1.90 install --git https://github.com/openvm-org/openvm.git --locked --force cargo-openvm

WORKDIR /app
# Copy only Rust workspace files to keep build cache stable when server/ changes
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ ./crates/
COPY bin/ ./bin/
COPY rustfmt.toml ./

# Build guest ELF and place where host expects it
WORKDIR /app/bin/stateless-guest
RUN RUSTFLAGS="" OPENVM_RUST_TOOLCHAIN=nightly-2026-01-01 cargo openvm build --no-transpile --profile=release \
    && mkdir -p ../reth-benchmark/elf \
    && cp target/riscv32im-risc0-zkvm-elf/release/openvm-stateless-guest ../reth-benchmark/elf/

# Build host binary
WORKDIR /app
ENV JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true"
ARG FEATURES="metrics,jemalloc,tco,unprotected,cuda"
ARG PROFILE="release"
ENV CUDA_ARCH="89"
RUN cargo +nightly-2026-01-01 build --bin openvm-reth-benchmark --profile=${PROFILE} --no-default-features --features=${FEATURES}

# Runtime image
FROM nvidia/cuda:12.8.1-runtime-ubuntu24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv curl tar gzip \
    && rm -rf /var/lib/apt/lists/*
RUN S5CMD_VER=$(curl -s https://api.github.com/repos/peak/s5cmd/releases/latest | \
    grep tag_name | cut -d '"' -f 4) && \
    S5CMD_VER_TRIMMED=$(printf "%s" "$S5CMD_VER" | sed 's/^v//') && \
    curl -L -o /tmp/s5cmd.tar.gz "https://github.com/peak/s5cmd/releases/download/${S5CMD_VER}/s5cmd_${S5CMD_VER_TRIMMED}_Linux-64bit.tar.gz" && \
    tar xvf /tmp/s5cmd.tar.gz -C /usr/local/bin s5cmd && \
    rm /tmp/s5cmd.tar.gz

WORKDIR /app
COPY --from=builder /app/target/release/openvm-reth-benchmark /usr/local/bin/openvm-reth-benchmark
COPY --from=builder /app/bin/openvm-reth-benchmark/elf/openvm-stateless-guest /app/bin/openvm-reth-benchmark/elf/openvm-stateless-guest
COPY server /app/server

RUN python3 -m venv /opt/venv \
    && . /opt/venv/bin/activate \
    && pip install --no-cache-dir -r /app/server/requirements.txt

ENV RUST_LOG="info,p3_=warn" \
    OUTPUT_PATH="metrics.json" \
    JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true" \
    KZG_PARAMS_DIR="/root/.openvm/params"

# Useful mounts for cache/params
VOLUME ["/app/rpc-cache", "/root/.openvm/params"]

ENV PATH="/opt/venv/bin:${PATH}" \
    OVM_BIN="/usr/local/bin/openvm-reth-benchmark"

EXPOSE 8000
ENTRYPOINT ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
