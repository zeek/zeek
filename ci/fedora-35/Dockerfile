FROM fedora:35

RUN dnf -y install \
    bison \
    cmake \
    diffutils \
    findutils \
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
    which \
    zlib-devel \
  && dnf clean all && rm -rf /var/cache/dnf

RUN pip3 install junit2html
