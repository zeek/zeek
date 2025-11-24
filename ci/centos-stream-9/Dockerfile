FROM quay.io/centos/centos:stream9

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION=20250905

# dnf config-manager isn't available at first, and
# we need it to install the CRB repo below.
RUN dnf -y install 'dnf-command(config-manager)'

# What used to be powertools is now called "CRB".
# We need it for some of the packages installed below.
# https://docs.fedoraproject.org/en-US/epel/
RUN dnf config-manager --set-enabled crb
RUN dnf -y install \
    https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
    https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-9.noarch.rpm

# The --nobest flag is hopefully temporary. Without it we currently hit
# package versioning conflicts around OpenSSL.
RUN dnf -y --nobest install \
    bison \
    ccache \
    cmake \
    cppzmq-devel \
    diffutils \
    flex \
    gcc-toolset-12-gcc \
    gcc-toolset-12-gcc-c++ \
    git \
    jq \
    libpcap-devel \
    make \
    openssl \
    openssl-devel \
    procps-ng \
    python3.13 \
    python3.13-devel \
    python3.13-pip\
    sqlite \
    swig \
    tar \
    which \
    zlib-devel \
  && dnf clean all && rm -rf /var/cache/dnf

# Set the crypto policy to allow SHA-1 certificates - which we have in our tests
RUN dnf -y --nobest install crypto-policies-scripts && update-crypto-policies --set LEGACY

# Override the default python3.9 installation paths with 3.13
RUN alternatives --install /usr/bin/python3 python3 /usr/bin/python3.13 10
RUN alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.13 10

# Override the default gcc 11 installation paths with gcc 12
RUN alternatives --install /usr/bin/cc cc /usr/bin/gcc-12 100
RUN alternatives --install /usr/bin/c++ c++ /usr/bin/g++-12 100

RUN pip3 install websockets junit2html
