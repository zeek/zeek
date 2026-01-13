
.. image:: /images/zeek-logo-text.png
   :align: center

==================
Zeek Documentation
==================

.. important::

  Make sure to read the :ref:`appropriate documentation version
  <documentation-versioning>`.

The purpose of this manual is to assist the Zeek community with implementing
Zeek in their environments. It includes material on Zeek's unique
capabilities, how to install it, how to interpret the default logs that Zeek
generates, and how to modify Zeek to fit your needs. This documentation is the
result of a volunteer community effort. If you would like to contribute, or
want more information, please visit the `Zeek web page
<https://zeek.org/getting-started-in-the-zeek-community/>`_ for details on how
to connect with the community.

.. toctree::
   :maxdepth: 2
   :caption: Table of Contents

   get-started
   about
   monitoring
   log-formats
   logs/index
   scripting/index
   frameworks/index
   customizations
   troubleshooting
   script-reference/index
   devel/index
   components/index
   acknowledgements

* :ref:`Index <genindex>`

.. _documentation-versioning:

Documentation Versioning
========================

.. attention::

  Zeek publishes both *feature* and *long-term support* releases. By default,
  the Zeek documentation at `docs.zeek.org <https://docs.zeek.org>`_ points
  to whichever release is the most recent (or *current*). In the current
  documentation, you may also find a dropdown menu in the banner, which lets
  you select the documentation version. For your convenience, the most used
  versions are:

    * Current release: `docs.zeek.org/en/current
      <https://docs.zeek.org/en/current>`_
    * Long-term support release: `docs.zeek.org/en/lts
      <https://docs.zeek.org/en/lts>`_
    * Git ``master`` branch: `docs.zeek.org/en/master
      <https://docs.zeek.org/en/master>`_

  We typically keep the last version from each release cycle available.
  The current release cycle(s) (LTS and/or feature) will have all versions
  available, but some may be hidden in the UI dropdown menu.

  Zeek's version numbering scheme is described in the `Release Cadence
  <https://github.com/zeek/zeek/wiki/Release-Cadence>`_ policy.
