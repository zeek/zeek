:tocdepth: 3

base/protocols/ftp/files.zeek
=============================
.. zeek:namespace:: FTP


:Namespace: FTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/ftp/info.zeek </scripts/base/protocols/ftp/info.zeek>`, :doc:`base/protocols/ftp/main.zeek </scripts/base/protocols/ftp/main.zeek>`, :doc:`base/protocols/ftp/utils.zeek </scripts/base/protocols/ftp/utils.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================================= =
:zeek:type:`FTP::Info`: :zeek:type:`record`                   
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef` 
============================================================= =

Functions
#########
====================================================== =====================================
:zeek:id:`FTP::describe_file`: :zeek:type:`function`   Describe the file being transferred.
:zeek:id:`FTP::get_file_handle`: :zeek:type:`function` Default file handle provider for FTP.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: FTP::describe_file

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Describe the file being transferred.

.. zeek:id:: FTP::get_file_handle

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for FTP.


