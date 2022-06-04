FROM alpine:latest

# A version field to invalide Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20220519

RUN apk add --no-cache \
  ccache \
  cmake \
  make \
  g++ \
  python3 \
  python3-dev \
  flex-dev \
  bison \
  libpcap-dev \
  openssl-dev \
  zlib-dev \
  swig \
  bash \
  bsd-compat-headers \
  linux-headers \
  fts-dev \
  git \
  curl \
  openssh-client \
  py3-pip

RUN pip3 install websockets junit2html
