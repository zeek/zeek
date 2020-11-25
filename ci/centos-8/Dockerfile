FROM centos:8

RUN dnf -y install epel-release dnf-plugins-core \
  && dnf clean all && rm -rf /var/cache/dnf

RUN dnf config-manager --set-enabled PowerTools

RUN dnf -y update && dnf -y install \
    git \
    cmake3 \
    make \
    gcc \
    gcc-c++ \
    flex \
    bison \
    swig \
    openssl \
    openssl-devel \
    libpcap-devel \
    python3 \
    python3-devel \
    python3-pip \
    zlib-devel \
    libsqlite3x-devel \
    findutils \
    which \
  && dnf clean all && rm -rf /var/cache/dnf

RUN pip3 install junit2html
