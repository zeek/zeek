:tocdepth: 3

base/protocols/ssl/files.bro
============================
.. bro:namespace:: SSL


:Namespace: SSL
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/ssl/main.bro </scripts/base/protocols/ssl/main.bro>`, :doc:`base/utils/conn-ids.bro </scripts/base/utils/conn-ids.bro>`

Summary
~~~~~~~
Redefinitions
#############
========================================= =
:bro:type:`SSL::Info`: :bro:type:`record` 
========================================= =

Functions
#########
==================================================== =====================================
:bro:id:`SSL::describe_file`: :bro:type:`function`   Default file describer for SSL.
:bro:id:`SSL::get_file_handle`: :bro:type:`function` Default file handle provider for SSL.
==================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: SSL::describe_file

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`) : :bro:type:`string`

   Default file describer for SSL.

.. bro:id:: SSL::get_file_handle

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Default file handle provider for SSL.


