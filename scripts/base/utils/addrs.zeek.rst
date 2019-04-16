:tocdepth: 3

base/utils/addrs.zeek
=====================

Functions for parsing and manipulating IP and MAC addresses.


Summary
~~~~~~~
Constants
#########
============================================================ =
:bro:id:`ip_addr_regex`: :bro:type:`pattern`                 
:bro:id:`ipv4_addr_regex`: :bro:type:`pattern`               
:bro:id:`ipv6_8hex_regex`: :bro:type:`pattern`               
:bro:id:`ipv6_addr_regex`: :bro:type:`pattern`               
:bro:id:`ipv6_compressed_hex4dec_regex`: :bro:type:`pattern` 
:bro:id:`ipv6_compressed_hex_regex`: :bro:type:`pattern`     
:bro:id:`ipv6_hex4dec_regex`: :bro:type:`pattern`            
============================================================ =

Functions
#########
========================================================================= =========================================================================
:bro:id:`addr_to_uri`: :bro:type:`function`                               Returns the string representation of an IP address suitable for inclusion
                                                                          in a URI.
:bro:id:`extract_ip_addresses`: :bro:type:`function`                      Extracts all IP (v4 or v6) address strings from a given string.
:bro:id:`find_ip_addresses`: :bro:type:`function` :bro:attr:`&deprecated` Extracts all IP (v4 or v6) address strings from a given string.
:bro:id:`has_valid_octets`: :bro:type:`function`                          Checks if all elements of a string array are a valid octet value.
:bro:id:`is_valid_ip`: :bro:type:`function`                               Checks if a string appears to be a valid IPv4 or IPv6 address.
:bro:id:`normalize_mac`: :bro:type:`function`                             Given a string, extracts the hex digits and returns a MAC address in
                                                                          the format: 00:a0:32:d7:81:8f.
========================================================================= =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: ip_addr_regex

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?((^?((^?((^?((^?([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})$?)|(^?(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})$?))$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?))$?))$?)|(^?((([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?/


.. bro:id:: ipv4_addr_regex

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})$?/


.. bro:id:: ipv6_8hex_regex

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})$?/


.. bro:id:: ipv6_addr_regex

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?((^?((^?((^?(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?))$?))$?)|(^?((([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?)|(^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?))$?/


.. bro:id:: ipv6_compressed_hex4dec_regex

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?/


.. bro:id:: ipv6_compressed_hex_regex

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?((([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?))$?/


.. bro:id:: ipv6_hex4dec_regex

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?((([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+))$?/


Functions
#########
.. bro:id:: addr_to_uri

   :Type: :bro:type:`function` (a: :bro:type:`addr`) : :bro:type:`string`

   Returns the string representation of an IP address suitable for inclusion
   in a URI.  For IPv4, this does no special formatting, but for IPv6, the
   address is included in square brackets.
   

   :a: the address to make suitable for URI inclusion.
   

   :returns: the string representation of the address suitable for URI inclusion.

.. bro:id:: extract_ip_addresses

   :Type: :bro:type:`function` (input: :bro:type:`string`) : :bro:type:`string_vec`

   Extracts all IP (v4 or v6) address strings from a given string.
   

   :input: a string that may contain an IP address anywhere within it.
   

   :returns: an array containing all valid IP address strings found in *input*.

.. bro:id:: find_ip_addresses

   :Type: :bro:type:`function` (input: :bro:type:`string`) : :bro:type:`string_array`
   :Attributes: :bro:attr:`&deprecated`

   Extracts all IP (v4 or v6) address strings from a given string.
   

   :input: a string that may contain an IP address anywhere within it.
   

   :returns: an array containing all valid IP address strings found in *input*.

.. bro:id:: has_valid_octets

   :Type: :bro:type:`function` (octets: :bro:type:`string_vec`) : :bro:type:`bool`

   Checks if all elements of a string array are a valid octet value.
   

   :octets: an array of strings to check for valid octet values.
   

   :returns: T if every element is between 0 and 255, inclusive, else F.

.. bro:id:: is_valid_ip

   :Type: :bro:type:`function` (ip_str: :bro:type:`string`) : :bro:type:`bool`

   Checks if a string appears to be a valid IPv4 or IPv6 address.
   

   :ip_str: the string to check for valid IP formatting.
   

   :returns: T if the string is a valid IPv4 or IPv6 address format.

.. bro:id:: normalize_mac

   :Type: :bro:type:`function` (a: :bro:type:`string`) : :bro:type:`string`

   Given a string, extracts the hex digits and returns a MAC address in
   the format: 00:a0:32:d7:81:8f. If the string doesn't contain 12 or 16 hex
   digits, an empty string is returned.
   

   :a: the string to normalize.
   

   :returns: a normalized MAC address, or an empty string in the case of an error.


