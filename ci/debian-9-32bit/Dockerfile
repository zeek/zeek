FROM i386/debian:9

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

RUN update-alternatives --install /usr/bin/cc cc /usr/bin/clang-7 100
RUN update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-7 100

RUN pip3 install junit2html

ENV CXXFLAGS=-stdlib=libc++
