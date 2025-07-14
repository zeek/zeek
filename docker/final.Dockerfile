# See the file "COPYING" in the main distribution directory for copyright.

# Final layer containing all artifacts.
FROM debian:bookworm-slim

# Make the shell split commands in the log so we can determine reasons for
# failures more easily.
SHELL ["/bin/sh", "-x", "-c"]

# Allow apt to retry 3 times before failing.
RUN echo 'Acquire::Retries "3";' > /etc/apt/apt.conf.d/80-retries

# Force apt to timeout retrieval of data after 3 minutes.
RUN echo 'Acquire::http::timeout "180";' > /etc/apt/apt.conf.d/99-timeouts
RUN echo 'Acquire::https::timeout "180";' >> /etc/apt/apt.conf.d/99-timeouts

RUN apt-get -q update \
 && apt-get install -q -y --no-install-recommends \
     ca-certificates \
     git \
     jq \
     libmaxminddb0 \
     libnode108 \
     libpcap0.8 \
     libpython3.11 \
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
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Copy over Zeek installation from build
COPY --from=zeek-build /usr/local/zeek /usr/local/zeek
ENV PATH="/usr/local/zeek/bin:${PATH}"
ENV PYTHONPATH="/usr/local/zeek/lib/zeek/python:${PYTHONPATH}"
