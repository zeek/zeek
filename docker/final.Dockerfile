# See the file "COPYING" in the main distribution directory for copyright.

# Final layer containing all artifacts.
FROM debian:13-slim

# Make the shell split commands in the log so we can determine reasons for
# failures more easily.
SHELL ["/bin/sh", "-x", "-c"]

# Allow apt to retry 3 times before failing.
RUN echo 'Acquire::Retries "3";' > /etc/apt/apt.conf.d/80-retries

# Force apt to timeout retrieval of data after 3 minutes.
RUN echo 'Acquire::http::timeout "180";' > /etc/apt/apt.conf.d/99-timeouts
RUN echo 'Acquire::https::timeout "180";' >> /etc/apt/apt.conf.d/99-timeouts

RUN apt-get -q update \
 && apt-get upgrade -q -y \
 && apt-get install -q -y --no-install-recommends \
     ca-certificates \
     git \
     jq \
     libmaxminddb0 \
     libnode115 \
     libpcap0.8 \
     libpython3.13 \
     libssl3 \
     libuv1 \
     libz1 \
     libzmq5 \
     net-tools \
     procps \
     python3-git \
     python3-minimal \
     python3-semantic-version \
     python3-websocket \
     python3-websockets \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Copy over Zeek installation from build
COPY --from=zeek-build /usr/local/zeek /usr/local/zeek
ENV PATH="/usr/local/zeek/bin:${PATH}"
ENV PYTHONPATH="/usr/local/zeek/lib/zeek/python:${PYTHONPATH}"

# OpenContainers annotation labels.
# See https://github.com/opencontainers/image-spec/blob/main/annotations.md
# for more details.
ARG ZEEK_VERSION
ARG GIT_COMMIT
ARG CREATED_DATE
LABEL org.opencontainers.image.created=$CREATED_DATE
LABEL org.opencontainers.image.authors="info@zeek.org"
LABEL org.opencontainers.image.url="https://zeek.org"
LABEL org.opencontainers.image.documentation="https://docs.zeek.org"
LABEL org.opencontainers.image.source="https://github.com/zeek/zeek"
LABEL org.opencontainers.image.version=$ZEEK_VERSION
LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.vendor="The Zeek Project"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
#LABEL org.opencontainers.image.ref.name=
LABEL org.opencontainers.image.title="Zeek"
LABEL org.opencontainers.image.description="Zeek is a powerful network analysis framework that is much different from the typical IDS you may know."
#LABEL org.opencontainers.image.base.digest=
#LABEL org.opencontainers.image.base.name=
