:tocdepth: 3

base/utils/urls.zeek
====================

Functions for URL handling.


Summary
~~~~~~~
Redefinable Options
###################
=========================================================== ======================================================
:bro:id:`url_regex`: :bro:type:`pattern` :bro:attr:`&redef` A regular expression for matching and extracting URLs.
=========================================================== ======================================================

Types
#####
=================================== ============================================
:bro:type:`URI`: :bro:type:`record` A URI, as parsed by :bro:id:`decompose_uri`.
=================================== ============================================

Functions
#########
============================================================ ==================================================
:bro:id:`decompose_uri`: :bro:type:`function`                
:bro:id:`find_all_urls`: :bro:type:`function`                Extracts URLs discovered in arbitrary text.
:bro:id:`find_all_urls_without_scheme`: :bro:type:`function` Extracts URLs discovered in arbitrary text without
                                                             the URL scheme included.
============================================================ ==================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: url_regex

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?(^([a-zA-Z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*))$?/

   A regular expression for matching and extracting URLs.

Types
#####
.. bro:type:: URI

   :Type: :bro:type:`record`

      scheme: :bro:type:`string` :bro:attr:`&optional`
         The URL's scheme..

      netlocation: :bro:type:`string`
         The location, which could be a domain name or an IP address. Left empty if not
         specified.

      portnum: :bro:type:`count` :bro:attr:`&optional`
         Port number, if included in URI.

      path: :bro:type:`string`
         Full including the file name. Will be '/' if there's not path given.

      file_name: :bro:type:`string` :bro:attr:`&optional`
         Full file name, including extension, if there is a file name.

      file_base: :bro:type:`string` :bro:attr:`&optional`
         The base filename, without extension, if there is a file name.

      file_ext: :bro:type:`string` :bro:attr:`&optional`
         The filename's extension, if there is a file name.

      params: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&optional`
         A table of all query parameters, mapping their keys to values, if there's a
         query.

   A URI, as parsed by :bro:id:`decompose_uri`.

Functions
#########
.. bro:id:: decompose_uri

   :Type: :bro:type:`function` (uri: :bro:type:`string`) : :bro:type:`URI`


.. bro:id:: find_all_urls

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`string_set`

   Extracts URLs discovered in arbitrary text.

.. bro:id:: find_all_urls_without_scheme

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`string_set`

   Extracts URLs discovered in arbitrary text without
   the URL scheme included.


