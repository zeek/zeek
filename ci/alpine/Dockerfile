FROM alpine:latest

# A version field used by Circle to create new versions on DockerHub
# during rebuilds.
ENV DOCKERFILE_VERSION=8.0-20260618

RUN apk add --no-cache \
  bash \
  bison \
  bsd-compat-headers \
  ccache \
  cmake \
  cppzmq \
  curl \
  diffutils \
  dnsmasq \
  flex-dev \
  musl-fts-dev \
  g++ \
  git \
  jq \
  libpcap-dev \
  linux-headers \
  make \
  openssh-client \
  openssl \
  openssl-dev \
  procps \
  py3-pip \
  python3 \
  python3-dev \
  swig \
  zlib-dev

RUN pip3 install --break-system-packages websockets junit2html
