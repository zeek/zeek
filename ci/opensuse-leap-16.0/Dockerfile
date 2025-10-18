FROM opensuse/leap:16.0

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION=20251017

RUN zypper refresh \
 && zypper in -y \
    bison \
    ccache \
    cmake \
    curl \
    dnsmasq \
    flex \
    gcc \
    gcc-c++ \
    git \
    gzip \
    jq \
    libopenssl-devel \
    libpcap-devel \
    make \
    openssh \
    procps \
    python313 \
    python313-devel \
    python313-pip \
    swig \
    tar \
    which \
    zlib-devel \
  && rm -rf /var/cache/zypp

# There isn't any version of cppzmq in the repos for Leap 16.0, and the version of libzmq
# doesn't have a devel package that includes the headers. Install both of them manually.
RUN git clone --depth 1 --branch v4.3.5 https://github.com/zeromq/libzmq.git \
 && cmake -B libzmq/build libzmq \
 && cmake --build libzmq/build \
 && cmake --install libzmq/build

RUN git clone --depth 1 --branch v4.11.0 https://github.com/zeromq/cppzmq.git \
 && cmake -B cppzmq/build cppzmq \
 && cmake --build cppzmq/build \
 && cmake --install cppzmq/build

RUN pip3 install websockets junit2html
