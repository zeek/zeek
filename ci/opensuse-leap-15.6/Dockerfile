FROM opensuse/leap:15.6

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION=20250905

RUN zypper addrepo https://download.opensuse.org/repositories/openSUSE:Leap:15.6:Update/standard/openSUSE:Leap:15.6:Update.repo \
 && zypper refresh \
 && zypper in -y \
    bison \
    ccache \
    cmake \
    curl \
    dnsmasq \
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
    procps \
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

# Leap 15.6 ships ZeroMQ 4.2.3 from 2017, install a newer version.
ENV ZEROMQ_VERSION=4.3.5
ENV ZEROMQ_SHA1=bdbf686c8a40ba638e21cf74e34dbb425e108500
RUN cd /opt \
    && curl -L https://github.com/zeromq/libzmq/releases/download/v${ZEROMQ_VERSION}/zeromq-${ZEROMQ_VERSION}.tar.gz -o zeromq-${ZEROMQ_VERSION}.tar.gz \
    && echo "${ZEROMQ_SHA1} zeromq-${ZEROMQ_VERSION}.tar.gz" | sha1sum -c \
    && tar xf zeromq-${ZEROMQ_VERSION}.tar.gz \
    && (cd ./zeromq-${ZEROMQ_VERSION} && ./configure --prefix=/usr/local && make -j && make install) \
    && rm -rf zeromq-${ZEROMQ_VERSION}*
