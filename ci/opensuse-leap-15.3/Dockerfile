FROM opensuse/leap:15.3

# A version field to invalide Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20220519

RUN zypper addrepo https://download.opensuse.org/repositories/openSUSE:Leap:15.2:Update/standard/openSUSE:Leap:15.2:Update.repo \
 && zypper refresh \
 && zypper in -y \
  ccache \
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

RUN pip3 install websockets junit2html

RUN update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-9 100
RUN update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-9 100
