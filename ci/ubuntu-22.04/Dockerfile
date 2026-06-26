FROM ubuntu:22.04

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field used by Circle to create new versions on DockerHub
# during rebuilds.
ENV DOCKERFILE_VERSION=20260515

RUN apt-get update && apt-get -y install \
    bc \
    bison \
    bsdmainutils \
    ccache \
    cmake \
    curl \
    flex \
    g++-12 \
    gcc-12 \
    git \
    jq \
    lcov \
    libkrb5-dev \
    libmaxminddb-dev \
    libpcap-dev \
    libssl-dev \
    libzmq3-dev \
    make \
    python3 \
    python3-dev \
    python3-pip\
    python3-venv \
    ruby \
    sqlite3 \
    swig \
    unzip \
    wget \
    zlib1g-dev \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*

 RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 0 \
  && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 0

RUN pip3 install websockets junit2html
RUN gem install coveralls-lcov
