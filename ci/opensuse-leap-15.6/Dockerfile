FROM opensuse/leap:15.6

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20230905

RUN zypper addrepo https://download.opensuse.org/repositories/openSUSE:Leap:15.6:Update/standard/openSUSE:Leap:15.6:Update.repo \
 && zypper refresh \
 && zypper in -y \
    bison \
    ccache \
    cmake \
    curl \
    flex \
    gcc12 \
    gcc12-c++ \
    git \
    gzip \
    jq \
    libopenssl-devel \
    libpcap-devel \
    make \
    openssh \
    python312 \
    python312-devel \
    python312-pip \
    swig \
    tar \
    which \
    zlib-devel \
  && rm -rf /var/cache/zypp

RUN update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.12 100
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 100
RUN update-alternatives --install /usr/bin/python3-config python3-config /usr/bin/python3.12-config 100

RUN pip3 install websockets junit2html

RUN update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-12 100
RUN update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-12 100
