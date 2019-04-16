:tocdepth: 3

base/protocols/conn/contents.zeek
=================================
.. bro:namespace:: Conn

This script can be used to extract either the originator's data or the 
responders data or both.  By default nothing is extracted, and in order 
to actually extract data the ``c$extract_orig`` and/or the
``c$extract_resp`` variable must be set to ``T``.  One way to achieve this
would be to handle the :bro:id:`connection_established` event elsewhere
and set the ``extract_orig`` and ``extract_resp`` options there.
However, there may be trouble with the timing due to event queue delay.

.. note::

   This script does not work well in a cluster context unless it has a
   remotely mounted disk to write the content files to.

:Namespace: Conn
:Imports: :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================== ==================================================================
:bro:id:`Conn::default_extract`: :bro:type:`bool` :bro:attr:`&redef`     If this variable is set to ``T``, then all contents of all
                                                                         connections will be extracted.
:bro:id:`Conn::extraction_prefix`: :bro:type:`string` :bro:attr:`&redef` The prefix given to files containing extracted connections as they
                                                                         are opened on disk.
======================================================================== ==================================================================

Redefinitions
#############
========================================== =
:bro:type:`connection`: :bro:type:`record` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Conn::default_extract

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If this variable is set to ``T``, then all contents of all
   connections will be extracted.

.. bro:id:: Conn::extraction_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"contents"``

   The prefix given to files containing extracted connections as they
   are opened on disk.


