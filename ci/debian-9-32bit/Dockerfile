FROM i386/debian:9

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field to invalide Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20220519

ENV CMAKE_DIR "/opt/cmake"
ENV CMAKE_VERSION "3.19.1"
ENV PATH "${CMAKE_DIR}/bin:${PATH}"

RUN apt-get update && apt-get -y install \
    ccache \
    git \
    clang-11 \
    make \
    flex \
    bison \
    libc++-11-dev \
    libc++abi-11-dev \
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
  # Recent CMake.
  && mkdir -p "${CMAKE_DIR}" \
  && curl -sSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz" | tar xzf - -C "${CMAKE_DIR}" --strip-components 1

RUN update-alternatives --install /usr/bin/cc cc /usr/bin/clang-11 100
RUN update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-11 100

# junit2html >= 31.0.0 requires jinj2 >= 3.0 which requires python >= 3.7 which is
# a higher version of python3 than debian 9 provides. Fix the version of junit2html
# to the last version before they required the newer jinja2.
RUN pip3 install websockets junit2html==30.0.6

ENV CXXFLAGS=-stdlib=libc++
