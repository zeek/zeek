:tocdepth: 3

base/utils/urls.zeek
====================

Functions for URL handling.


Summary
~~~~~~~
Redefinable Options
###################
============================================================== ======================================================
:zeek:id:`url_regex`: :zeek:type:`pattern` :zeek:attr:`&redef` A regular expression for matching and extracting URLs.
============================================================== ======================================================

Types
#####
===================================== =============================================
:zeek:type:`URI`: :zeek:type:`record` A URI, as parsed by :zeek:id:`decompose_uri`.
===================================== =============================================

Functions
#########
============================================================== ==================================================
:zeek:id:`decompose_uri`: :zeek:type:`function`                
:zeek:id:`find_all_urls`: :zeek:type:`function`                Extracts URLs discovered in arbitrary text.
:zeek:id:`find_all_urls_without_scheme`: :zeek:type:`function` Extracts URLs discovered in arbitrary text without
                                                               the URL scheme included.
============================================================== ==================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: url_regex
   :source-code: base/utils/urls.zeek 7 7

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?(^([a-zA-Z\-]{3,5}):\/\/(-\.)?([^[:blank:]\/?\.#-]+\.?)+(\/[^[:blank:]]*)?)$?/


   A regular expression for matching and extracting URLs.
   This is the @imme_emosol regex from https://mathiasbynens.be/demo/url-regex, adapted for Zeek. It's
   not perfect for all of their test cases, but it's one of the shorter ones that covers most of the
   test cases.

Types
#####
.. zeek:type:: URI
   :source-code: base/utils/urls.zeek 10 29

   :Type: :zeek:type:`record`


   .. zeek:field:: scheme :zeek:type:`string` :zeek:attr:`&optional`

      The URL's scheme..


   .. zeek:field:: netlocation :zeek:type:`string`

      The location, which could be a domain name or an IP address. Left empty if not
      specified.


   .. zeek:field:: portnum :zeek:type:`count` :zeek:attr:`&optional`

      Port number, if included in URI.


   .. zeek:field:: path :zeek:type:`string`

      Full including the file name. Will be '/' if there's not path given.


   .. zeek:field:: file_name :zeek:type:`string` :zeek:attr:`&optional`

      Full file name, including extension, if there is a file name.


   .. zeek:field:: file_base :zeek:type:`string` :zeek:attr:`&optional`

      The base filename, without extension, if there is a file name.


   .. zeek:field:: file_ext :zeek:type:`string` :zeek:attr:`&optional`

      The filename's extension, if there is a file name.


   .. zeek:field:: params :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&optional`

      A table of all query parameters, mapping their keys to values, if there's a
      query.


   A URI, as parsed by :zeek:id:`decompose_uri`.

Functions
#########
.. zeek:id:: decompose_uri
   :source-code: base/utils/urls.zeek 52 135

   :Type: :zeek:type:`function` (uri: :zeek:type:`string`) : :zeek:type:`URI`


.. zeek:id:: find_all_urls
   :source-code: base/utils/urls.zeek 32 35

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string_set`

   Extracts URLs discovered in arbitrary text.

.. zeek:id:: find_all_urls_without_scheme
   :source-code: base/utils/urls.zeek 39 50

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string_set`

   Extracts URLs discovered in arbitrary text without
   the URL scheme included.


