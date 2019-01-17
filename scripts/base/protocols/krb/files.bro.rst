:tocdepth: 3

base/protocols/krb/files.bro
============================
.. bro:namespace:: KRB


:Namespace: KRB
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/krb/main.bro </scripts/base/protocols/krb/main.bro>`, :doc:`base/utils/conn-ids.bro </scripts/base/utils/conn-ids.bro>`

Summary
~~~~~~~
Redefinitions
#############
========================================= =
:bro:type:`KRB::Info`: :bro:type:`record` 
========================================= =

Functions
#########
==================================================== =====================================
:bro:id:`KRB::describe_file`: :bro:type:`function`   Default file describer for KRB.
:bro:id:`KRB::get_file_handle`: :bro:type:`function` Default file handle provider for KRB.
==================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: KRB::describe_file

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`) : :bro:type:`string`

   Default file describer for KRB.

.. bro:id:: KRB::get_file_handle

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Default file handle provider for KRB.


