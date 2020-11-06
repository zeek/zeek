FROM fedora:31

RUN yum -y install \
    bison \
    cmake \
    diffutils \
    findutils \
    flex \
    git \
    gcc \
    gcc-c++ \
    libpcap-devel \
    make \
    openssl \
    openssl-devel \
    python3 \
    python3-devel \
    python3-pip\
    sqlite \
    swig \
    which \
    zlib-devel \
  && yum clean all && rm -rf /var/cache/yum

# Many distros adhere to PEP 394's recommendation for `python` = `python2` so
# this is a simple workaround until we drop Python 2 support and explicitly
# use `python3` for all invocations (e.g. in shebangs).
RUN ln -sf /usr/bin/python3 /usr/local/bin/python
RUN ln -sf /usr/bin/pip3 /usr/local/bin/pip

RUN pip install junit2html
