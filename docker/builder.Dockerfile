# See the file "COPYING" in the main distribution directory for copyright.

# Layer to build Zeek.
FROM debian:bookworm-slim

# Make the shell split commands in the log so we can determine reasons for
# failures more easily.
SHELL ["/bin/sh", "-x", "-c"]

# Allow apt to retry 3 times before failing.
RUN echo 'Acquire::Retries "3";' > /etc/apt/apt.conf.d/80-retries

# Force apt to timeout retrieval of data after 3 minutes.
RUN echo 'Acquire::http::timeout "180";' > /etc/apt/apt.conf.d/99-timeouts
RUN echo 'Acquire::https::timeout "180";' >> /etc/apt/apt.conf.d/99-timeouts

# Configure system for build.
RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
     bind9 \
     bison \
     ccache \
     cmake \
     curl \
     flex \
     g++ \
     gcc \
     git \
     libcurl4-openssl-dev \
     libfl2 \
     libfl-dev \
     libnode-dev \
     libmaxminddb-dev \
     libpcap-dev \
     libssl-dev \
     libuv1-dev \
     libz-dev \
     make \
     python3-minimal \
     python3.11-dev \
     swig \
     ninja-build \
     python3-pip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Tell git all the repositories are safe.
RUN git config --global --add safe.directory '*'
