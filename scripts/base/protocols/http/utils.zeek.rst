:tocdepth: 3

base/protocols/http/utils.zeek
==============================
.. bro:namespace:: HTTP

Utilities specific for HTTP processing.

:Namespace: HTTP
:Imports: :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`

Summary
~~~~~~~
Functions
#########
==================================================== ====================================================================
:bro:id:`HTTP::build_url`: :bro:type:`function`      Creates a URL from an :bro:type:`HTTP::Info` record.
:bro:id:`HTTP::build_url_http`: :bro:type:`function` Creates a URL from an :bro:type:`HTTP::Info` record.
:bro:id:`HTTP::describe`: :bro:type:`function`       Create an extremely shortened representation of a log line.
:bro:id:`HTTP::extract_keys`: :bro:type:`function`   Given a string containing a series of key-value pairs separated
                                                     by "=", this function can be used to parse out all of the key names.
==================================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: HTTP::build_url

   :Type: :bro:type:`function` (rec: :bro:type:`HTTP::Info`) : :bro:type:`string`

   Creates a URL from an :bro:type:`HTTP::Info` record.  This should
   handle edge cases such as proxied requests appropriately.
   

   :rec: An :bro:type:`HTTP::Info` record.
   

   :returns: A URL, not prefixed by ``"http://"``.

.. bro:id:: HTTP::build_url_http

   :Type: :bro:type:`function` (rec: :bro:type:`HTTP::Info`) : :bro:type:`string`

   Creates a URL from an :bro:type:`HTTP::Info` record.  This should
   handle edge cases such as proxied requests appropriately.
   

   :rec: An :bro:type:`HTTP::Info` record.
   

   :returns: A URL prefixed with ``"http://"``.

.. bro:id:: HTTP::describe

   :Type: :bro:type:`function` (rec: :bro:type:`HTTP::Info`) : :bro:type:`string`

   Create an extremely shortened representation of a log line.

.. bro:id:: HTTP::extract_keys

   :Type: :bro:type:`function` (data: :bro:type:`string`, kv_splitter: :bro:type:`pattern`) : :bro:type:`string_vec`

   Given a string containing a series of key-value pairs separated
   by "=", this function can be used to parse out all of the key names.
   

   :data: The raw data, such as a URL or cookie value.
   

   :kv_splitter: A regular expression representing the separator between
                key-value pairs.
   

   :returns: A vector of strings containing the keys.


