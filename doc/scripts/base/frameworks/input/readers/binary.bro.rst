:tocdepth: 3

base/frameworks/input/readers/binary.bro
========================================
.. bro:namespace:: InputBinary

Interface for the binary input reader.

:Namespace: InputBinary

Summary
~~~~~~~
Redefinable Options
###################
======================================================================= ==========================================================
:bro:id:`InputBinary::chunk_size`: :bro:type:`count` :bro:attr:`&redef` Size of data chunks to read from the input file at a time.
======================================================================= ==========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: InputBinary::chunk_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1024``

   Size of data chunks to read from the input file at a time.


