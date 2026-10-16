FROM ubuntu:26.04

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

RUN apt-get update && apt-get --no-install-recommends -y install \
    git \
    gzip \
    libpcap-dev \
    python3-scapy \
    tar \
    tcpdump \
    tcpreplay \
    tshark \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*
