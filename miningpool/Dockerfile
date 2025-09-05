FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config \
    libjansson-dev libcurl4-openssl-dev libzmq3-dev \
    ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ckpool
COPY . .

RUN set -eux; \
    if [ -x ./autogen.sh ]; then ./autogen.sh; fi; \
    ./configure; \
    make -j"$(nproc)"

# nessun entrypoint: fai tutto da compose
CMD ["./src/ckpool", "-c", "./ckpool.conf"]

