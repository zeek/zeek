:tocdepth: 3

base/utils/strings.bro
======================

Functions to assist with small string analysis and manipulation that can
be implemented as Bro functions and don't need to be implemented as built-in
functions.


Summary
~~~~~~~
Functions
#########
================================================ =============================================================================
:bro:id:`cut_tail`: :bro:type:`function`         Cut a number of characters from the end of the given string.
:bro:id:`is_string_binary`: :bro:type:`function` Returns true if the given string is at least 25% composed of 8-bit
                                                 characters.
:bro:id:`join_string_set`: :bro:type:`function`  Join a set of strings together, with elements delimited by a constant string.
:bro:id:`string_escape`: :bro:type:`function`    Given a string, returns an escaped version.
================================================ =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: cut_tail

   :Type: :bro:type:`function` (s: :bro:type:`string`, tail_len: :bro:type:`count`) : :bro:type:`string`

   Cut a number of characters from the end of the given string.
   

   :s: a string to trim.
   

   :tail_len: the number of characters to remove from the end of the string.
   

   :returns: the given string with *tail_len* characters removed from the end.

.. bro:id:: is_string_binary

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`bool`

   Returns true if the given string is at least 25% composed of 8-bit
   characters.

.. bro:id:: join_string_set

   :Type: :bro:type:`function` (ss: :bro:type:`set` [:bro:type:`string`], j: :bro:type:`string`) : :bro:type:`string`

   Join a set of strings together, with elements delimited by a constant string.
   

   :ss: a set of strings to join.
   

   :j: the string used to join set elements.
   

   :returns: a string composed of all elements of the set, delimited by the
            joining string.

.. bro:id:: string_escape

   :Type: :bro:type:`function` (s: :bro:type:`string`, chars: :bro:type:`string`) : :bro:type:`string`

   Given a string, returns an escaped version.
   

   :s: a string to escape.
   

   :chars: a string containing all the characters that need to be escaped.
   

   :returns: a string with all occurrences of any character in *chars* escaped
            using ``\``, and any literal ``\`` characters likewise escaped.


