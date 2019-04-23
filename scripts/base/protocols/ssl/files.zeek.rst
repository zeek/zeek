:tocdepth: 3

base/protocols/ssl/files.zeek
=============================
.. zeek:namespace:: SSL


:Namespace: SSL
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/ssl/main.zeek </scripts/base/protocols/ssl/main.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== =
:zeek:type:`SSL::Info`: :zeek:type:`record` 
=========================================== =

Functions
#########
====================================================== =====================================
:zeek:id:`SSL::describe_file`: :zeek:type:`function`   Default file describer for SSL.
:zeek:id:`SSL::get_file_handle`: :zeek:type:`function` Default file handle provider for SSL.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: SSL::describe_file

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for SSL.

.. zeek:id:: SSL::get_file_handle

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for SSL.


