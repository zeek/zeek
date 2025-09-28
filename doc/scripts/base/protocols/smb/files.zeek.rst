:tocdepth: 3

base/protocols/smb/files.zeek
=============================
.. zeek:namespace:: SMB


:Namespace: SMB
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/smb/main.zeek </scripts/base/protocols/smb/main.zeek>`

Summary
~~~~~~~
Functions
#########
====================================================== =====================================
:zeek:id:`SMB::describe_file`: :zeek:type:`function`   Default file describer for SMB.
:zeek:id:`SMB::get_file_handle`: :zeek:type:`function` Default file handle provider for SMB.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: SMB::describe_file
   :source-code: base/protocols/smb/files.zeek 36 48

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for SMB.

.. zeek:id:: SMB::get_file_handle
   :source-code: base/protocols/smb/files.zeek 14 34

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for SMB.


