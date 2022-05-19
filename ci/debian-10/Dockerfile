FROM debian:10

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

ENV CMAKE_DIR "/opt/cmake"
ENV CMAKE_VERSION "3.19.1"

RUN apt-get update && apt-get -y install \
    git \
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
  && rm -rf /var/lib/apt/lists/* \
  # Install a recent CMake to build Spicy.
  && mkdir -p "${CMAKE_DIR}" \
  && curl -sSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz" | tar xzf - -C "${CMAKE_DIR}" --strip-components 1 \

  && pip3 install junit2html

ENV PATH "${CMAKE_DIR}/bin:${PATH}"
