# See the file "COPYING" in the main distribution directory for copyright.

# Layer to build Zeek.
FROM debian:buster-slim AS build_zeek

# Configure system for build.
RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
     bind9 \
     bison \
     cmake \
     flex \
     g++ \
     gcc \
     libmaxminddb-dev \
     libpcap-dev \
     libssl-dev \
     libz-dev \
     make \
     python3-minimal \
     python3-dev \
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

WORKDIR /src/zeek
RUN ./configure \
     --generator=Ninja \
     --build-type=Release \
 && ninja -C build install

# Final layer containing all artifacts.
FROM debian:buster-slim AS final

RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
     ca-certificates \
     git \
     libmaxminddb0 \
     libpython3.7 \
     libpcap0.8 \
     libssl1.1 \
     libz1 \
     python3-minimal \
     python3-git \
     python3-semantic-version \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Copy over Zeek installation.
COPY --from=build_zeek /usr/local/zeek /usr/local/zeek
ENV PATH "/usr/local/zeek/bin:${PATH}"
