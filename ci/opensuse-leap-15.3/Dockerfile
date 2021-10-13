FROM opensuse/leap:15.3

RUN zypper in -y \
  cmake \
  make \
  gcc \
  gcc-c++ \
  python3 \
  python3-devel \
  flex \
  bison \
  libpcap-devel \
  libopenssl-devel \
  zlib-devel \
  swig \
  git \
  curl \
  python3-pip \
  which \
  gzip \
  tar \
  && rm -rf /var/cache/zypp


RUN pip3 install junit2html
