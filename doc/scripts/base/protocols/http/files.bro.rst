:tocdepth: 3

base/protocols/http/files.bro
=============================
.. bro:namespace:: HTTP


:Namespace: HTTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/http/entities.bro </scripts/base/protocols/http/entities.bro>`, :doc:`base/protocols/http/main.bro </scripts/base/protocols/http/main.bro>`, :doc:`base/protocols/http/utils.bro </scripts/base/protocols/http/utils.bro>`, :doc:`base/utils/conn-ids.bro </scripts/base/utils/conn-ids.bro>`

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


