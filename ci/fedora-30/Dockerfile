FROM fedora:30

RUN yum -y install \
    git \
    cmake \
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
    python3-pip\
    zlib-devel \
    sqlite \
    findutils \
    which \
  && yum clean all && rm -rf /var/cache/yum

# Many distros adhere to PEP 394's recommendation for `python` = `python2` so
# this is a simple workaround until we drop Python 2 support and explicitly
# use `python3` for all invocations (e.g. in shebangs).
RUN ln -sf /usr/bin/python3 /usr/local/bin/python
RUN ln -sf /usr/bin/pip3 /usr/local/bin/pip

RUN pip install junit2html
