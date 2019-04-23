:tocdepth: 3

base/protocols/smtp/files.zeek
==============================
.. zeek:namespace:: SMTP


:Namespace: SMTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/smtp/entities.zeek </scripts/base/protocols/smtp/entities.zeek>`, :doc:`base/protocols/smtp/main.zeek </scripts/base/protocols/smtp/main.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =
:zeek:type:`SMTP::Info`: :zeek:type:`record` 
============================================ =

Functions
#########
======================================================= ======================================
:zeek:id:`SMTP::describe_file`: :zeek:type:`function`   Default file describer for SMTP.
:zeek:id:`SMTP::get_file_handle`: :zeek:type:`function` Default file handle provider for SMTP.
======================================================= ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: SMTP::describe_file

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for SMTP.

.. zeek:id:: SMTP::get_file_handle

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for SMTP.


