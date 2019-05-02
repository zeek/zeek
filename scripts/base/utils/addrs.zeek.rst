:tocdepth: 3

base/utils/addrs.zeek
=====================

Functions for parsing and manipulating IP and MAC addresses.


Summary
~~~~~~~
Constants
#########
============================================================== =
:zeek:id:`ip_addr_regex`: :zeek:type:`pattern`                 
:zeek:id:`ipv4_addr_regex`: :zeek:type:`pattern`               
:zeek:id:`ipv6_8hex_regex`: :zeek:type:`pattern`               
:zeek:id:`ipv6_addr_regex`: :zeek:type:`pattern`               
:zeek:id:`ipv6_compressed_hex4dec_regex`: :zeek:type:`pattern` 
:zeek:id:`ipv6_compressed_hex_regex`: :zeek:type:`pattern`     
:zeek:id:`ipv6_hex4dec_regex`: :zeek:type:`pattern`            
============================================================== =

Functions
#########
====================================================== =========================================================================
:zeek:id:`addr_to_uri`: :zeek:type:`function`          Returns the string representation of an IP address suitable for inclusion
                                                       in a URI.
:zeek:id:`extract_ip_addresses`: :zeek:type:`function` Extracts all IP (v4 or v6) address strings from a given string.
:zeek:id:`has_valid_octets`: :zeek:type:`function`     Checks if all elements of a string array are a valid octet value.
:zeek:id:`is_valid_ip`: :zeek:type:`function`          Checks if a string appears to be a valid IPv4 or IPv6 address.
:zeek:id:`normalize_mac`: :zeek:type:`function`        Given a string, extracts the hex digits and returns a MAC address in
                                                       the format: 00:a0:32:d7:81:8f.
====================================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: ip_addr_regex

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?((^?((^?((^?((^?([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})$?)|(^?(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})$?))$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?))$?))$?)|(^?((([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?/


.. zeek:id:: ipv4_addr_regex

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})$?/


.. zeek:id:: ipv6_8hex_regex

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})$?/


.. zeek:id:: ipv6_addr_regex

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?((^?((^?((^?(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?))$?))$?)|(^?((([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?/


.. zeek:id:: ipv6_compressed_hex4dec_regex

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?/


.. zeek:id:: ipv6_compressed_hex_regex

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?))$?/


.. zeek:id:: ipv6_hex4dec_regex

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?((([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?/


Functions
#########
.. zeek:id:: addr_to_uri

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`string`

   Returns the string representation of an IP address suitable for inclusion
   in a URI.  For IPv4, this does no special formatting, but for IPv6, the
   address is included in square brackets.
   

   :a: the address to make suitable for URI inclusion.
   

   :returns: the string representation of the address suitable for URI inclusion.

.. zeek:id:: extract_ip_addresses

   :Type: :zeek:type:`function` (input: :zeek:type:`string`) : :zeek:type:`string_vec`

   Extracts all IP (v4 or v6) address strings from a given string.
   

   :input: a string that may contain an IP address anywhere within it.
   

   :returns: an array containing all valid IP address strings found in *input*.

.. zeek:id:: has_valid_octets

   :Type: :zeek:type:`function` (octets: :zeek:type:`string_vec`) : :zeek:type:`bool`

   Checks if all elements of a string array are a valid octet value.
   

   :octets: an array of strings to check for valid octet values.
   

   :returns: T if every element is between 0 and 255, inclusive, else F.

.. zeek:id:: is_valid_ip

   :Type: :zeek:type:`function` (ip_str: :zeek:type:`string`) : :zeek:type:`bool`

   Checks if a string appears to be a valid IPv4 or IPv6 address.
   

   :ip_str: the string to check for valid IP formatting.
   

   :returns: T if the string is a valid IPv4 or IPv6 address format.

.. zeek:id:: normalize_mac

   :Type: :zeek:type:`function` (a: :zeek:type:`string`) : :zeek:type:`string`

   Given a string, extracts the hex digits and returns a MAC address in
   the format: 00:a0:32:d7:81:8f. If the string doesn't contain 12 or 16 hex
   digits, an empty string is returned.
   

   :a: the string to normalize.
   

   :returns: a normalized MAC address, or an empty string in the case of an error.


