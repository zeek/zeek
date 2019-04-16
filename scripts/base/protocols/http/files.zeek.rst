:tocdepth: 3

base/protocols/http/files.zeek
==============================
.. bro:namespace:: HTTP


:Namespace: HTTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/http/entities.zeek </scripts/base/protocols/http/entities.zeek>`, :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/protocols/http/utils.zeek </scripts/base/protocols/http/utils.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Functions
#########
===================================================== ======================================
:bro:id:`HTTP::describe_file`: :bro:type:`function`   Default file describer for HTTP.
:bro:id:`HTTP::get_file_handle`: :bro:type:`function` Default file handle provider for HTTP.
===================================================== ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: HTTP::describe_file

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`) : :bro:type:`string`

   Default file describer for HTTP.

.. bro:id:: HTTP::get_file_handle

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Default file handle provider for HTTP.


