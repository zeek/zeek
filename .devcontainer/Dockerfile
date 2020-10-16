# [Choice] Debian / Ubuntu version: debian-10, debian-9
ARG VARIANT=buster
FROM mcr.microsoft.com/vscode/devcontainers/cpp:dev-${VARIANT}

# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
  && apt-get -y install --no-install-recommends cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev ninja-build
