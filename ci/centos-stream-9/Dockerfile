FROM quay.io/centos/centos:stream9

# dnf config-manager isn't available at first, and
# we need it to install the CRB repo below.
RUN dnf -y install 'dnf-command(config-manager)'

# What used to be powertools is now called "CRB".
# We need it for some of the packages installed below.
# https://docs.fedoraproject.org/en-US/epel/
RUN dnf config-manager --set-enabled crb
RUN dnf -y install \
    https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
    https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-9.noarch.rpm

# The --nobest flag is hopefully temporary. Without it we currently hit
# package versioning conflicts around OpenSSL.
RUN dnf -y --nobest install \
    bison \
    cmake \
    diffutils \
    flex \
    git \
    gcc \
    gcc-c++ \
    libpcap-devel \
    make \
    openssl-devel \
    python3-devel \
    python3-pip\
    sqlite \
    swig \
    which \
    zlib-devel \
  && dnf clean all && rm -rf /var/cache/dnf

RUN pip3 install junit2html
