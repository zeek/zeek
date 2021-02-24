FROM quay.io/centos/centos:stream8

RUN dnf config-manager --set-enabled powertools

RUN dnf -y install \
    bison \
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

RUN pip3 install junit2html
