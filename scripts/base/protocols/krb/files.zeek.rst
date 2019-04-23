:tocdepth: 3

base/protocols/krb/files.zeek
=============================
.. zeek:namespace:: KRB


:Namespace: KRB
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/krb/main.zeek </scripts/base/protocols/krb/main.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== =
:zeek:type:`KRB::Info`: :zeek:type:`record` 
=========================================== =

Functions
#########
====================================================== =====================================
:zeek:id:`KRB::describe_file`: :zeek:type:`function`   Default file describer for KRB.
:zeek:id:`KRB::get_file_handle`: :zeek:type:`function` Default file handle provider for KRB.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: KRB::describe_file

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for KRB.

.. zeek:id:: KRB::get_file_handle

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for KRB.


