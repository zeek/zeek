# See the file "COPYING" in the main distribution directory for copyright.

# Layer to build Zeek.
FROM debian:13-slim

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
 && apt-get upgrade -q -y \
 && apt-get install -q -y --no-install-recommends \
     bind9 \
     bison \
     ccache \
     cmake \
     cppzmq-dev \
     flex \
     g++ \
     gcc \
     git \
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
     python3-dev \
     swig \
     ninja-build \
     python3-pip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Tell git all the repositories are safe.
RUN git config --global --add safe.directory '*'

# OpenContainers annotation labels. We only care about the revision label for
# the builder image since it gets cached on Cirrus. The full set of labels is
# set in the final image.
# See https://github.com/opencontainers/image-spec/blob/main/annotations.md
# for more details.
ARG GIT_COMMIT
LABEL org.opencontainers.image.revision=$GIT_COMMIT
