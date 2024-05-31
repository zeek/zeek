FROM alpine:latest

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20230823

RUN apk add --no-cache \
  bash \
  bison \
  bsd-compat-headers \
  ccache \
  cmake \
  curl \
  diffutils \
  flex-dev \
  musl-fts-dev \
  g++ \
  git \
  jq \
  libpcap-dev \
  linux-headers \
  make \
  openssh-client \
  openssl-dev \
  procps \
  py3-pip \
  py3-websockets \
  python3 \
  python3-dev \
  swig \
  zlib-dev

RUN pip3 install --break-system-packages junit2html
