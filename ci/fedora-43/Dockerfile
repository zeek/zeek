FROM fedora:43

# A version field used by Circle to create new versions on DockerHub
# during rebuilds.
ENV DOCKERFILE_VERSION=8.2-20260618

RUN dnf -y install \
    bison \
    ccache \
    cmake \
    cppzmq-devel \
    diffutils \
    findutils \
    flex \
    gawk \
    gcc \
    gcc-c++ \
    git \
    jq \
    libpcap-devel \
    make \
    nodejs-devel \
    openssl \
    openssl-devel \
    procps-ng \
    python3 \
    python3-devel \
    python3-pip\
    sqlite \
    swig \
    which \
    zlib-devel \
    crypto-policies-scripts \
  && dnf clean all && rm -rf /var/cache/dnf

RUN pip3 install websockets junit2html
