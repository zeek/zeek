FROM centos:7

# A version field to invalidate Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20240514

ENV FLEX_VERSION=2.6.4
ENV FLEX_DIR=/opt/flex

# Disabled lookup of fastest mirror since the list seems to be outdated and no valid mirror can be detected.
RUN sed -i 's/enabled=1/enabled=0/' /etc/yum/pluginconf.d/fastestmirror.conf

# mirrorlist.centos.org doesn't exist anymore. Replace uses of it with vault.centos.org.
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
RUN sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
RUN sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo

# The version of git in the standard repos is 1.8 and CI needs 2.3+
# for the use of GIT_SSH_COMMAND when cloning private repos.
RUN yum -y install \
    https://repo.ius.io/ius-release-el7.rpm \
    https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
  && yum -y install git236 ccache \
  && yum clean all && rm -rf /var/cache/yum

RUN yum -y install \
    epel-release \
  && yum clean all && rm -rf /var/cache/yum

RUN yum -y install \
    centos-release-scl \
  && yum clean all && rm -rf /var/cache/yum

# This has to be run a second time due to the additional repositories that were
# added above. The first pass allows those to be installed. The second pass
# updates the new ones and allows everything else to be installed.
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
RUN sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
RUN sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo

RUN yum -y install \
    devtoolset-8 \
  && yum clean all && rm -rf /var/cache/yum

RUN yum -y install \
    bison \
    cmake3 \
    curl \
    findutils \
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

# Install a recent flex for Spicy.
RUN curl -sSL "https://github.com/westes/flex/releases/download/v${FLEX_VERSION}/flex-${FLEX_VERSION}.tar.gz" | tar xzf - -C /tmp \
 && (cd /tmp/flex-${FLEX_VERSION} \
     && ./configure --prefix=${FLEX_DIR} \
     && make -j`nproc` install) \
 && rm -rf /tmp/flex-${FLEX_VERSION}

RUN pip3 install websockets junit2html

RUN echo 'unset BASH_ENV PROMPT_COMMAND ENV' > /usr/bin/zeek-ci-env && \
    echo 'source /opt/rh/devtoolset-8/enable' >> /usr/bin/zeek-ci-env && \
    echo 'export PATH=${PATH}:${FLEX_DIR}/bin' >> /usr/bin/zeek-ci-env

ENV BASH_ENV="/usr/bin/zeek-ci-env" \
    ENV="/usr/bin/zeek-ci-env" \
    PROMPT_COMMAND=". /usr/bin/zeek-ci-env"
