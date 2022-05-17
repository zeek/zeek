FROM opensuse/leap:15.3

RUN zypper addrepo https://download.opensuse.org/repositories/openSUSE:Leap:15.2:Update/standard/openSUSE:Leap:15.2:Update.repo \
 && zypper refresh \
 && zypper in -y \
  cmake \
  make \
  gcc9 \
  gcc9-c++ \
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

ENV CXX g++-9
ENV CC gcc-9
