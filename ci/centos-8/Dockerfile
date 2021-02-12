FROM centos:8

RUN dnf -y install epel-release dnf-plugins-core \
  && dnf clean all && rm -rf /var/cache/dnf

RUN dnf config-manager --set-enabled powertools

RUN dnf -y update && dnf -y install \
    git \
    cmake3 \
    make \
    gcc \
    gcc-c++ \
    flex \
    bison \
    swig \
    openssl \
    openssl-devel \
    libpcap-devel \
    python3 \
    python3-devel \
    python3-pip \
    zlib-devel \
    libsqlite3x-devel \
    findutils \
    diffutils \
    which \
  && dnf clean all && rm -rf /var/cache/dnf

# Many distros adhere to PEP 394's recommendation for `python` = `python2` so
# this is a simple workaround until we drop Python 2 support and explicitly
# use `python3` for all invocations (e.g. in shebangs).
RUN ln -sf /usr/bin/python3 /usr/local/bin/python
RUN ln -sf /usr/bin/pip3 /usr/local/bin/pip

RUN pip install junit2html
