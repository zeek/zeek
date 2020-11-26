FROM ubuntu:16.04

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

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
    clang-8 \
    libc++-8-dev \
    libc++abi-8-dev \
    swig \
    zlib1g-dev \
    libkrb5-dev \
    bsdmainutils \
    sqlite3 \
    curl \
    wget \
    xz-utils \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install junit2html

ENV CC=/usr/bin/clang-8
ENV CXX=/usr/bin/clang++-8
ENV CXXFLAGS=-stdlib=libc++
