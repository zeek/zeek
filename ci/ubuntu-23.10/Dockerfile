FROM ubuntu:23.10

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20230828

RUN apt-get update && apt-get -y install \
    bc \
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
    libmaxminddb-dev \
    libpcap-dev \
    libssl-dev \
    make \
    python3 \
    python3-dev \
    python3-pip \
    python3-websockets \
    ruby \
    sqlite3 \
    swig \
    unzip \
    wget \
    zlib1g-dev \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages junit2html
