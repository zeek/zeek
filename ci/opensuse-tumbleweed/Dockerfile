FROM opensuse/tumbleweed

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20230801

# Remove the repo-openh264 repository, it caused intermittent issues
# and we should not be needing any packages from it.
RUN zypper modifyrepo --disable repo-openh264 || true

RUN zypper refresh \
 && zypper in -y \
    awk \
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
    libcurl-devel \
    libopenssl-devel \
    libpcap-devel \
    make \
    openssh \
    python3 \
    python3-devel \
    python3-pip \
    python3-websockets \
    swig \
    tar \
    util-linux \
    which \
    zlib-devel \
  && rm -rf /var/cache/zypp

RUN pip3 install --break-system-packages junit2html
