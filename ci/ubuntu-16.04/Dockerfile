FROM ubuntu:16.04

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
  && rm -rf /var/lib/apt/lists/*

RUN wget -q https://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
RUN mkdir /clang-9
RUN tar --strip-components=1 -C /clang-9 -xvf clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
RUN update-alternatives --install /usr/bin/cc cc /clang-9/bin/clang 100
RUN update-alternatives --install /usr/bin/c++ c++ /clang-9/bin/clang++ 100

# Many distros adhere to PEP 394's recommendation for `python` = `python2` so
# this is a simple workaround until we drop Python 2 support and explicitly
# use `python3` for all invocations (e.g. in shebangs).
RUN ln -sf /usr/bin/python3 /usr/local/bin/python
RUN ln -sf /usr/bin/pip3 /usr/local/bin/pip

RUN pip install junit2html

ENV CXXFLAGS=-stdlib=libc++
ENV LD_LIBRARY_PATH=/clang-9/lib
