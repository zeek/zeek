:tocdepth: 3

base/protocols/ftp/files.bro
============================
.. bro:namespace:: FTP


:Namespace: FTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/ftp/info.bro </scripts/base/protocols/ftp/info.bro>`, :doc:`base/protocols/ftp/main.bro </scripts/base/protocols/ftp/main.bro>`, :doc:`base/protocols/ftp/utils.bro </scripts/base/protocols/ftp/utils.bro>`, :doc:`base/utils/conn-ids.bro </scripts/base/utils/conn-ids.bro>`

Summary
~~~~~~~
Redefinitions
#############
========================================================== =
:bro:type:`FTP::Info`: :bro:type:`record`                  
:bro:type:`fa_file`: :bro:type:`record` :bro:attr:`&redef` 
========================================================== =

Functions
#########
==================================================== =====================================
:bro:id:`FTP::describe_file`: :bro:type:`function`   Describe the file being transferred.
:bro:id:`FTP::get_file_handle`: :bro:type:`function` Default file handle provider for FTP.
==================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: FTP::describe_file

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`) : :bro:type:`string`

   Describe the file being transferred.

.. bro:id:: FTP::get_file_handle

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Default file handle provider for FTP.


