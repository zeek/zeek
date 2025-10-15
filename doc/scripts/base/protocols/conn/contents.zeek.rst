:tocdepth: 3

base/protocols/conn/contents.zeek
=================================
.. zeek:namespace:: Conn

This script can be used to extract either the originator's data or the
responders data or both.  By default nothing is extracted, and in order
to actually extract data the ``c$extract_orig`` and/or the
``c$extract_resp`` variable must be set to ``T``.  One way to achieve this
would be to handle the :zeek:id:`connection_established` event elsewhere
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
=========================================================================== ==================================================================
:zeek:id:`Conn::default_extract`: :zeek:type:`bool` :zeek:attr:`&redef`     If this variable is set to ``T``, then all contents of all
                                                                            connections will be extracted.
:zeek:id:`Conn::extraction_prefix`: :zeek:type:`string` :zeek:attr:`&redef` The prefix given to files containing extracted connections as they
                                                                            are opened on disk.
=========================================================================== ==================================================================

Redefinitions
#############
============================================ ==================================================================================================================
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               extract_orig: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`Conn::default_extract` :zeek:attr:`&optional`
                                             
                                               extract_resp: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`Conn::default_extract` :zeek:attr:`&optional`
============================================ ==================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Conn::default_extract
   :source-code: base/protocols/conn/contents.zeek 25 25

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If this variable is set to ``T``, then all contents of all
   connections will be extracted.

.. zeek:id:: Conn::extraction_prefix
   :source-code: base/protocols/conn/contents.zeek 21 21

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"contents"``

   The prefix given to files containing extracted connections as they
   are opened on disk.


