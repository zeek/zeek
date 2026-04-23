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
    zeromq-devel \
    zlib-devel \
    libzip-devel \
  && rm -rf /var/cache/zypp

RUN pip3 install websockets junit2html
