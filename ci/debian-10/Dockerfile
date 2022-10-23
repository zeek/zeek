FROM debian:10

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20220519

ENV CMAKE_DIR "/opt/cmake"
ENV CMAKE_VERSION "3.19.1"
ENV PATH "${CMAKE_DIR}/bin:${PATH}"

RUN apt-get update && apt-get -y install \
    bison \
    bsdmainutils \
    ccache \
    curl \
    flex \
    g++ \
    gcc \
    git \
    libkrb5-dev \
    libpcap-dev \
    libssl-dev \
    make \
    procps \
    python3 \
    python3-dev \
    python3-pip\
    sqlite3 \
    swig \
    wget \
    xz-utils \
    zlib1g-dev \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*

# Install a recent CMake to build Spicy.
RUN mkdir -p "${CMAKE_DIR}" \
  && curl -sSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz" | tar xzf - -C "${CMAKE_DIR}" --strip-components 1

RUN pip3 install websockets junit2html
