:tocdepth: 3

base/protocols/http/files.zeek
==============================
.. zeek:namespace:: HTTP


:Namespace: HTTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/http/entities.zeek </scripts/base/protocols/http/entities.zeek>`, :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/protocols/http/utils.zeek </scripts/base/protocols/http/utils.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Functions
#########
======================================================= ======================================
:zeek:id:`HTTP::describe_file`: :zeek:type:`function`   Default file describer for HTTP.
:zeek:id:`HTTP::get_file_handle`: :zeek:type:`function` Default file handle provider for HTTP.
======================================================= ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: HTTP::describe_file
   :source-code: base/protocols/http/files.zeek 37 49

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for HTTP.

.. zeek:id:: HTTP::get_file_handle
   :source-code: base/protocols/http/files.zeek 17 35

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for HTTP.


