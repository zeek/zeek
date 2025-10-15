:tocdepth: 3

base/utils/strings.zeek
=======================

Functions to assist with small string analysis and manipulation that can
be implemented as Zeek functions and don't need to be implemented as built-in
functions.


Summary
~~~~~~~
Functions
#########
================================================== ==================================================================
:zeek:id:`cut_tail`: :zeek:type:`function`         Cut a number of characters from the end of the given string.
:zeek:id:`is_string_binary`: :zeek:type:`function` Returns true if the given string is at least 25% composed of 8-bit
                                                   characters.
:zeek:id:`string_escape`: :zeek:type:`function`    Given a string, returns an escaped version.
================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: cut_tail
   :source-code: base/utils/strings.zeek 35 40

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, tail_len: :zeek:type:`count`) : :zeek:type:`string`

   Cut a number of characters from the end of the given string.
   

   :param s: a string to trim.
   

   :param tail_len: the number of characters to remove from the end of the string.
   

   :returns: the given string with *tail_len* characters removed from the end.

.. zeek:id:: is_string_binary
   :source-code: base/utils/strings.zeek 7 10

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`bool`

   Returns true if the given string is at least 25% composed of 8-bit
   characters.

.. zeek:id:: string_escape
   :source-code: base/utils/strings.zeek 20 26

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, chars: :zeek:type:`string`) : :zeek:type:`string`

   Given a string, returns an escaped version.
   

   :param s: a string to escape.
   

   :param chars: a string containing all the characters that need to be escaped.
   

   :returns: a string with all occurrences of any character in *chars* escaped
            using ``\``, and any literal ``\`` characters likewise escaped.


