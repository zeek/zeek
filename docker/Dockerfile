# See the file "COPYING" in the main distribution directory for copyright.

# Layer to build Zeek.
FROM debian:bullseye-slim AS build

# Configure system for build.
RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
     bind9 \
     bison \
     cmake \
     flex \
     g++ \
     gcc \
     libfl2 \
     libfl-dev \
     libmaxminddb-dev \
     libpcap-dev \
     libssl-dev \
     libz-dev \
     make \
     python3-minimal \
     python3.9-dev \
     swig \
     ninja-build \
     python3-pip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Copy over the Zeek source tree.
# NOTE: This assumes that we build in the context of the parent directory (the
# Git checkout root). We e.g., ensure that in the `Makefile` in this directory.
COPY . /src/zeek
RUN make -C /src/zeek distclean

ARG CONFFLAGS="--generator=Ninja --build-type=Release"

WORKDIR /src/zeek
RUN ./configure $CONFFLAGS && ninja -C build install

# Final layer containing all artifacts.
FROM debian:bullseye-slim AS final

RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
     ca-certificates \
     git \
     libmaxminddb0 \
     libpython3.9 \
     libpcap0.8 \
     libssl1.1 \
     libz1 \
     python3-minimal \
     python3-git \
     python3-semantic-version \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Copy over Zeek installation.
COPY --from=build /usr/local/zeek /usr/local/zeek
ENV PATH "/usr/local/zeek/bin:${PATH}"
ENV PYTHONPATH "/usr/local/zeek/lib/zeek/python:${PYTHONPATH}"
