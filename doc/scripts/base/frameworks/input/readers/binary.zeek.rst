:tocdepth: 3

base/frameworks/input/readers/binary.zeek
=========================================
.. zeek:namespace:: InputBinary

Interface for the binary input reader.

:Namespace: InputBinary

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ ==================================================================
:zeek:id:`InputBinary::chunk_size`: :zeek:type:`count` :zeek:attr:`&redef`   Size of data chunks to read from the input file at a time.
:zeek:id:`InputBinary::path_prefix`: :zeek:type:`string` :zeek:attr:`&redef` On input streams with a pathless or relative-path source filename,
                                                                             prefix the following path.
============================================================================ ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: InputBinary::chunk_size
   :source-code: base/frameworks/input/readers/binary.zeek 7 7

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1024``

   Size of data chunks to read from the input file at a time.

.. zeek:id:: InputBinary::path_prefix
   :source-code: base/frameworks/input/readers/binary.zeek 13 13

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   On input streams with a pathless or relative-path source filename,
   prefix the following path. This prefix can, but need not be, absolute.
   The default is to leave any filenames unchanged. This prefix has no
   effect if the source already is an absolute path.


