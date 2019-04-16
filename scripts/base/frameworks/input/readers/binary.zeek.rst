:tocdepth: 3

base/frameworks/input/readers/binary.zeek
=========================================
.. bro:namespace:: InputBinary

Interface for the binary input reader.

:Namespace: InputBinary

Summary
~~~~~~~
Redefinable Options
###################
========================================================================= ==================================================================
:bro:id:`InputBinary::chunk_size`: :bro:type:`count` :bro:attr:`&redef`   Size of data chunks to read from the input file at a time.
:bro:id:`InputBinary::path_prefix`: :bro:type:`string` :bro:attr:`&redef` On input streams with a pathless or relative-path source filename,
                                                                          prefix the following path.
========================================================================= ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: InputBinary::chunk_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1024``

   Size of data chunks to read from the input file at a time.

.. bro:id:: InputBinary::path_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   On input streams with a pathless or relative-path source filename,
   prefix the following path. This prefix can, but need not be, absolute.
   The default is to leave any filenames unchanged. This prefix has no
   effect if the source already is an absolute path.


