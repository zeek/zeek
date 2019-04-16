:tocdepth: 3

base/protocols/smb/files.zeek
=============================
.. bro:namespace:: SMB


:Namespace: SMB
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/smb/main.zeek </scripts/base/protocols/smb/main.zeek>`

Summary
~~~~~~~
Functions
#########
==================================================== =====================================
:bro:id:`SMB::describe_file`: :bro:type:`function`   Default file describer for SMB.
:bro:id:`SMB::get_file_handle`: :bro:type:`function` Default file handle provider for SMB.
==================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: SMB::describe_file

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`) : :bro:type:`string`

   Default file describer for SMB.

.. bro:id:: SMB::get_file_handle

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Default file handle provider for SMB.


