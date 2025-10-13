
.. _Homebrew: https://brew.sh
.. _zkg package manager: https://docs.zeek.org/projects/package-manager/en/stable/

.. _installing-zeek:

===============
Installing Zeek
===============

To run Zeek, grab our official Docker images, download our Linux binary
packages, install via Homebrew_ on your Mac, use the ports collections on FreeBSD
and OpenBSD. See the :doc:`building-from-source` section to build Zeek yourself.
For details about our release cadence and the significance of Zeek's version
numbers, please refer to our `Release Cadence
<https://github.com/zeek/zeek/wiki/Release-Cadence>`_ wiki page.

.. _docker-images:

Docker Images
=============

We provide official Docker images on Docker Hub at https://hub.docker.com/u/zeek

    * For the latest feature release: ``docker pull zeek/zeek:latest``
    * For the latest LTS release: ``docker pull zeek/zeek:lts``
    * For the latest release in a given series: ``docker pull zeek/zeek:7.2``
    * For a specific release: ``docker pull zeek/zeek:7.0.8``
    * For the nightly build: ``docker pull zeek/zeek-dev:latest``

Additionally, we push these images to Amazon's Public Elastic Container
Registry (ECR) in the `Zeek Project <https://gallery.ecr.aws/zeek>`_
public gallery. To use Amazon's container registry instead of Docker Hub,
prefix images with ``public.ecr.aws/zeek`` instead of ``zeek``.

    * For instance, to pull the latest feature release: ``docker pull public.ecr.aws/zeek/zeek:latest``

The images are Debian-based and feature a complete Zeek installation with ``zeek``,
``zkg``, and the Spicy toolchain, but are otherwise minimal to avoid bloat in
derived images. For example, if you'd like to install Zeek plugins in those
images, you'll need to install their needed toolchain, typically at least
``g++`` for compilation, ``cmake`` and ``make`` as build tools, and
``libpcap-dev`` to build against Zeek headers. Similarly, you'll need ``g++``
for Spicy's JIT compilation, as well as ``cmake`` and ``make`` to build Spicy
analyzer packages.

  .. code-block:: console

    apt-get update
    apt-get install -y --no-install-recommends g++ cmake make libpcap-dev

The source files used to create the container images are on
`GitHub <https://github.com/zeek/zeek/blob/master/docker>`_.

.. _binary-packages:

Binary Packages
===============

Linux
-----

We provide `binary packages <https://build.opensuse.org/project/show/security:zeek>`_
for a wide range of Linux distributions via the `openSUSE Build Service
<https://build.opensuse.org/>`_. To install, first add the relevant OBS
package repository to your system, then use your system's package manager
as usual.

We provide the following groups of packages:

    * ``zeek-X.0``: specific LTS release lines, currently `7.0.x <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-7.0>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-7.0>`__), `6.0.x <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-6.0>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-6.0>`__), and `5.0.x <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-5.0>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-5.0>`__).
    * ``zeek``: the `latest Zeek release <https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek>`__)
    * ``zeek-nightly``: our `nightly builds <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-nightly>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-nightly>`__)
    * ``zeek-rc``: our `release candidates <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-rc>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-rc>`__)

For example, for the latest Zeek 7.0 LTS release on Ubuntu 22.04 the steps look as follows:

  .. code-block:: console

     echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
     curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
     sudo apt update
     sudo apt install zeek-7.0

.. note:: Our motivation for this approach is twofold. First, it guarantees LTS
   users that they won't unexpectedly end up on a newer LTS line when it comes
   out. For example, when you install the ``zeek-6.0`` packages, you will not
   end up on Zeek 7.0 until you decide to switch. Second, it reflects the fact
   that we consider our x.1 and x.2 feature release lines transient, because
   they go out of support immediately once we move to the next line of feature
   releases. Therefore, users of the ``zeek`` packages automatically obtain the
   latest releases as we publish them.

   In the past our binary packages also automatically transitioned our LTS users
   to newer versions, via the older ``zeek-lts`` packages. These remain visible
   on OBS but are no longer supported.

The primary install prefix for binary packages is :file:`/opt/zeek` (depending
on which version you’re using), and includes a complete Zeek environment with
``zeek`` itself, the `zkg package manager`_, the Spicy toolchain, etc.

See our `Binary Packages wiki page <https://github.com/zeek/zeek/wiki/Binary-Packages>`_
for the latest updates on binary releases.

macOS
-----

The Zeek `Homebrew formula <https://formulae.brew.sh/formula/zeek>`_
provides binary packages ("bottles"). To install:

  .. code-block:: console

     brew install zeek

These packages are not maintained by the Zeek project.

FreeBSD
-------

Zeek is available from the `FreeBSD ports collection <https://www.freshports.org/security/zeek>`_.
To install:

  .. code-block:: console

     sudo pkg install -y zeek

These packages are not maintained by the Zeek project.

OpenBSD
-------

Zeek is available from the `OpenBSD ports collection <https://ports.to/path/net/bro.html>`_.
To install:

  .. code-block:: console

     doas pkg_add zeek

These packages are not maintained by the Zeek project.
