FROM golang:1.20 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    make \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY ./go-ethereum-1.11.0 /go/src/github.com/ethereum/go-ethereum

WORKDIR /go/src/github.com/ethereum/go-ethereum

ARG ACCOUNT_PASSWORD

COPY genesis.json /tmp

RUN make geth \
    && cp ./build/bin/geth /usr/local/bin/ \
    && geth init /tmp/genesis.json \
    && rm -f ~/.ethereum/geth/nodekey \
    && echo ${ACCOUNT_PASSWORD} > /tmp/password \
    && geth account new --password /tmp/password \
    && rm -f /tmp/password

ENTRYPOINT ["geth"]
