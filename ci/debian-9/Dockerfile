FROM debian:9

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field to invalide Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 221001

RUN apt-get update && apt-get -y install \
    git \
    cmake \
    make \
    gcc \
    g++ \
    flex \
    bison \
    libpcap-dev \
    libssl-dev \
    python3 \
    python3-dev \
    python3-pip\
    swig \
    zlib1g-dev \
    libkrb5-dev \
    bsdmainutils \
    sqlite3 \
    curl \
    wget \
    xz-utils \
    clang-7 \
    libc++-7-dev \
    libc++abi-7-dev \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install junit2html

ENV CC=/usr/bin/clang-7
ENV CXX=/usr/bin/clang++-7
ENV CXXFLAGS=-stdlib=libc++
