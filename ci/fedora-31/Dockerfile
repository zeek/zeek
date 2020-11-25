FROM fedora:31

RUN yum -y install \
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
    openssl \
    openssl-devel \
    python3 \
    python3-devel \
    python3-pip\
    sqlite \
    swig \
    which \
    zlib-devel \
  && yum clean all && rm -rf /var/cache/yum

RUN pip3 install junit2html
