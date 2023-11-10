FROM quay.io/centos/centos:stream8

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20230801

RUN dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
RUN dnf config-manager --set-enabled powertools

RUN dnf -y install \
    bison \
    ccache \
    cmake \
    diffutils \
    flex \
    gcc \
    gcc-c++ \
    git \
    libcurl-devel \
    libpcap-devel \
    make \
    openssl \
    openssl-devel \
    procps-ng \
    python38 \
    python38-devel \
    python38-pip\
    sqlite \
    swig \
    which \
    zlib-devel \
  && dnf clean all && rm -rf /var/cache/dnf

RUN pip3 install websockets junit2html
