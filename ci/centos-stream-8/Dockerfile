FROM quay.io/centos/centos:stream8

# A version field to invalide Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20220519

RUN dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
RUN dnf config-manager --set-enabled powertools

RUN dnf -y install \
    bison \
    ccache \
    cmake \
    diffutils \
    flex \
    git \
    gcc \
    gcc-c++ \
    libpcap-devel \
    make \
    openssl-devel \
    python3-devel \
    python3-pip\
    sqlite \
    swig \
    zlib-devel \
  && dnf clean all && rm -rf /var/cache/dnf

RUN pip3 install websockets junit2html
