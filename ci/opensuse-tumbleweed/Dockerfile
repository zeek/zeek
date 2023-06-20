FROM opensuse/tumbleweed

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20230620

# Remove the repo-openh264 repository, it caused intermittent issues
# and we should not be needing any packages from it.
RUN zypper modifyrepo --disable repo-openh264 || true

RUN zypper refresh \
 && zypper in -y \
    bison \
    ccache \
    cmake \
    curl \
    diffutils \
    findutils \
    flex \
    gcc \
    gcc-c++ \
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
    util-linux \
    which \
    zlib-devel \
  && rm -rf /var/cache/zypp

RUN pip3 install websockets junit2html
