:tocdepth: 3

base/protocols/http/utils.zeek
==============================
.. zeek:namespace:: HTTP

Utilities specific for HTTP processing.

:Namespace: HTTP
:Imports: :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`

Summary
~~~~~~~
Functions
#########
====================================================== ====================================================================
:zeek:id:`HTTP::build_url`: :zeek:type:`function`      Creates a URL from an :zeek:type:`HTTP::Info` record.
:zeek:id:`HTTP::build_url_http`: :zeek:type:`function` Creates a URL from an :zeek:type:`HTTP::Info` record.
:zeek:id:`HTTP::describe`: :zeek:type:`function`       Create an extremely shortened representation of a log line.
:zeek:id:`HTTP::extract_keys`: :zeek:type:`function`   Given a string containing a series of key-value pairs separated
                                                       by "=", this function can be used to parse out all of the key names.
====================================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: HTTP::build_url

   :Type: :zeek:type:`function` (rec: :zeek:type:`HTTP::Info`) : :zeek:type:`string`

   Creates a URL from an :zeek:type:`HTTP::Info` record.  This should
   handle edge cases such as proxied requests appropriately.
   

   :rec: An :zeek:type:`HTTP::Info` record.
   

   :returns: A URL, not prefixed by ``"http://"``.

.. zeek:id:: HTTP::build_url_http

   :Type: :zeek:type:`function` (rec: :zeek:type:`HTTP::Info`) : :zeek:type:`string`

   Creates a URL from an :zeek:type:`HTTP::Info` record.  This should
   handle edge cases such as proxied requests appropriately.
   

   :rec: An :zeek:type:`HTTP::Info` record.
   

   :returns: A URL prefixed with ``"http://"``.

.. zeek:id:: HTTP::describe

   :Type: :zeek:type:`function` (rec: :zeek:type:`HTTP::Info`) : :zeek:type:`string`

   Create an extremely shortened representation of a log line.

.. zeek:id:: HTTP::extract_keys

   :Type: :zeek:type:`function` (data: :zeek:type:`string`, kv_splitter: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Given a string containing a series of key-value pairs separated
   by "=", this function can be used to parse out all of the key names.
   

   :data: The raw data, such as a URL or cookie value.
   

   :kv_splitter: A regular expression representing the separator between
                key-value pairs.
   

   :returns: A vector of strings containing the keys.


