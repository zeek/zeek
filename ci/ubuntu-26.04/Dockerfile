FROM ubuntu:26.04

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field used by Circle to create new versions on DockerHub
# during rebuilds.
ENV DOCKERFILE_VERSION=20260515

RUN apt-get update && apt-get -y install \
    bc \
    bison \
    bsdmainutils \
    ccache \
    clang-18 \
    clang++-18 \
    cmake \
    cppzmq-dev \
    curl \
    dnsmasq \
    flex \
    g++ \
    gcc \
    git \
    jq \
    lcov \
    libkrb5-dev \
    libmaxminddb-dev \
    libpcap-dev \
    libssl-dev \
    make \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    ruby \
    sqlite3 \
    swig \
    unzip \
    wget \
    zlib1g-dev \
    libc++-dev \
    libc++abi-dev \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages websockets junit2html
RUN gem install coveralls-lcov
