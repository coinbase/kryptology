FROM golang:1.17 AS builder
# Install gomarkdoc
RUN GO111MODULE=on go get -u github.com/princjef/gomarkdoc/cmd/gomarkdoc

# Install rust and build spdx
COPY . /kryptology
WORKDIR /kryptology

RUN apt update && apt install -y curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs  -- | sh -s -- -y
RUN /root/.cargo/bin/cargo build --release --manifest-path=./cmd/spdx/Cargo.toml && \
    cp ./cmd/spdx/target/release/spdx /usr/bin/ && \
    chmod 755 /usr/bin/spdx
