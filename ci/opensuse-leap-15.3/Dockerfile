FROM opensuse/leap:15.3

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20220615

RUN zypper addrepo https://download.opensuse.org/repositories/openSUSE:Leap:15.3:Update/standard/openSUSE:Leap:15.3:Update.repo \
 && zypper refresh \
 && zypper in -y \
    bison \
    ccache \
    cmake \
    curl \
    flex \
    gcc9 \
    gcc9-c++ \
    git \
    gzip \
    libopenssl-devel \
    libpcap-devel \
    make \
    python3 \
    python3-devel \
    python3-pip \
    swig \
    tar \
    which \
    zlib-devel \
  && rm -rf /var/cache/zypp

RUN pip3 install websockets junit2html

RUN update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-9 100
RUN update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-9 100
