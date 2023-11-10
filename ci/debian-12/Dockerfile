FROM debian:bookworm

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20230801

RUN apt-get update && apt-get -y install \
    bison \
    bsdmainutils \
    ccache \
    cmake \
    curl \
    flex \
    g++ \
    gcc \
    git \
    libcurl4-openssl-dev \
    libkrb5-dev \
    libnode-dev \
    libpcap-dev \
    libssl-dev \
    libuv1-dev \
    make \
    python3 \
    python3-dev \
    python3-pip\
    python3-websockets \
    sqlite3 \
    swig \
    wget \
    xz-utils \
    zlib1g-dev \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*

# Debian bookworm really doesn't like using pip to install system wide stuff, but
# doesn't seem there's a python3-junit2html package, so not sure what we'd break.
RUN pip3 install --break-system-packages junit2html
