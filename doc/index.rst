
.. image:: /images/zeek-logo-text.png
   :align: center

==================
Zeek Documentation
==================

.. important::

  Make sure to read the :ref:`appropriate documentation version
  <documentation-versioning>`.

The purpose of this document is to assist the Zeek community with implementing
Zeek in their environments. The document includes material on Zeek's unique
capabilities, how to install it, how to interpret the default logs that Zeek
generates, and how to modify Zeek to fit your needs. The document is the
result of a volunteer community effort. If you would like to contribute, or
want more information, please visit the `Zeek web page
<https://zeek.org/getting-started-in-the-zeek-community/>`_ for details on how
to connect with the community.

.. toctree::
   :maxdepth: 2
   :caption: Table of Contents

   about
   monitoring
   get-started
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

  The Zeek codebase has three primary branches of interest to users so this
  document is also maintained as three different versions, one associated with
  each branch of Zeek.  The default version of `docs.zeek.org
  <https://docs.zeek.org>`_ tracks Zeek's latest Git development:

    * Git *master* branch: https://docs.zeek.org/en/master

  If you instead use a Zeek Long-Term Support (LTS) or Feature release these
  are the appropriate starting points:

    * Long-Term Support Release: https://docs.zeek.org/en/lts
    * Current Feature Release: https://docs.zeek.org/en/current

  To help clarify which release you are using, the version numbering
  scheme for the two release branches is described in the `Release
  Cadence <https://github.com/zeek/zeek/wiki/Release-Cadence>`_ policy.

  Documentation for older Zeek releases remains available for approximately one
  full major-version release cycle, i.e., about a year. You can browse recent
  versions via the fly-out menu in the bottom left, and find all available
  versions on the `RTD website <https://readthedocs.org/projects/zeek-docs/versions/>`_.
