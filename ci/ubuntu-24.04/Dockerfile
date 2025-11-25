FROM ubuntu:24.04

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION=20251125

RUN apt-get update && apt-get -y install \
    bc \
    bison \
    bsdmainutils \
    ccache \
    clang-19 \
    clang++-19 \
    clang-tidy-19 \
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
    libhiredis-dev \
    libkrb5-dev \
    libmaxminddb-dev \
    libnode-dev \
    libpcap-dev \
    libssl-dev \
    make \
    python3 \
    python3-dev \
    python3-git \
    python3-pip \
    python3-semantic-version \
    redis-server \
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

# Ubuntu installs clang versions with the binaries having the version number
# appended. Create a symlink for clang-tidy so cmake finds it correctly.
RUN update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-19 1000

# Download a newer pre-built ccache version that recognizes -fprofile-update=atomic
# which is used when building with --coverage.
#
# This extracts the tarball into /opt/ccache-<version>-<platform> and
# symlinks the executable to /usr/local/bin/ccache.
#
# See: https://ccache.dev/download.html
ENV CCACHE_VERSION=4.10.2
ENV CCACHE_PLATFORM=linux-x86_64
ENV CCACHE_URL=https://github.com/ccache/ccache/releases/download/v${CCACHE_VERSION}/ccache-${CCACHE_VERSION}-${CCACHE_PLATFORM}.tar.xz
ENV CCACHE_SHA256=80cab87bd510eca796467aee8e663c398239e0df1c4800a0b5dff11dca0b4f18
RUN cd /opt \
    && if [ "$(uname -p)" != "x86_64" ]; then echo "cannot use ccache pre-built for x86_64!" >&2; exit 1 ; fi \
    && curl -L --fail --max-time 30 $CCACHE_URL -o ccache.tar.xz \
    && sha256sum ./ccache.tar.xz >&2 \
    && echo "${CCACHE_SHA256} ccache.tar.xz" | sha256sum -c - \
    && tar xvf ./ccache.tar.xz \
    && ln -s $(pwd)/ccache-${CCACHE_VERSION}-${CCACHE_PLATFORM}/ccache /usr/local/bin/ccache \
    && test "$(command -v ccache)" = "/usr/local/bin/ccache" \
    && test "$(ccache --print-version)" = "${CCACHE_VERSION}" \
    && rm ./ccache.tar.xz
