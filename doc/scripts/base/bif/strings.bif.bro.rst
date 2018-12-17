:tocdepth: 3

base/bif/strings.bif.bro
========================
.. bro:namespace:: GLOBAL

Definitions of built-in functions related to string processing and
manipulation.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================================== ============================================================================
:bro:id:`cat_string_array`: :bro:type:`function` :bro:attr:`&deprecated`   Concatenates all elements in an array of strings.
:bro:id:`cat_string_array_n`: :bro:type:`function` :bro:attr:`&deprecated` Concatenates a specific range of elements in an array of strings.
:bro:id:`clean`: :bro:type:`function`                                      Replaces non-printable characters in a string with escaped sequences.
:bro:id:`edit`: :bro:type:`function`                                       Returns an edited version of a string that applies a special
                                                                           "backspace character" (usually ``\x08`` for backspace or ``\x7f`` for DEL).
:bro:id:`escape_string`: :bro:type:`function`                              Replaces non-printable characters in a string with escaped sequences.
:bro:id:`find_all`: :bro:type:`function`                                   Finds all occurrences of a pattern in a string.
:bro:id:`find_last`: :bro:type:`function`                                  Finds the last occurrence of a pattern in a string.
:bro:id:`gsub`: :bro:type:`function`                                       Substitutes a given replacement string for all occurrences of a pattern
                                                                           in a given string.
:bro:id:`hexdump`: :bro:type:`function`                                    Returns a hex dump for given input data.
:bro:id:`is_ascii`: :bro:type:`function`                                   Determines whether a given string contains only ASCII characters.
:bro:id:`join_string_array`: :bro:type:`function` :bro:attr:`&deprecated`  Joins all values in the given array of strings with a separator placed
                                                                           between each element.
:bro:id:`join_string_vec`: :bro:type:`function`                            Joins all values in the given vector of strings with a separator placed
                                                                           between each element.
:bro:id:`levenshtein_distance`: :bro:type:`function`                       Calculates the Levenshtein distance between the two strings.
:bro:id:`reverse`: :bro:type:`function`                                    Returns a reversed copy of the string
:bro:id:`sort_string_array`: :bro:type:`function` :bro:attr:`&deprecated`  Sorts an array of strings.
:bro:id:`split`: :bro:type:`function` :bro:attr:`&deprecated`              Splits a string into an array of strings according to a pattern.
:bro:id:`split1`: :bro:type:`function` :bro:attr:`&deprecated`             Splits a string *once* into a two-element array of strings according to a
                                                                           pattern.
:bro:id:`split_all`: :bro:type:`function` :bro:attr:`&deprecated`          Splits a string into an array of strings according to a pattern.
:bro:id:`split_n`: :bro:type:`function` :bro:attr:`&deprecated`            Splits a string a given number of times into an array of strings according
                                                                           to a pattern.
:bro:id:`split_string`: :bro:type:`function`                               Splits a string into an array of strings according to a pattern.
:bro:id:`split_string1`: :bro:type:`function`                              Splits a string *once* into a two-element array of strings according to a
                                                                           pattern.
:bro:id:`split_string_all`: :bro:type:`function`                           Splits a string into an array of strings according to a pattern.
:bro:id:`split_string_n`: :bro:type:`function`                             Splits a string a given number of times into an array of strings according
                                                                           to a pattern.
:bro:id:`str_shell_escape`: :bro:type:`function`                           Takes a string and escapes characters that would allow execution of
                                                                           commands at the shell level.
:bro:id:`str_smith_waterman`: :bro:type:`function`                         Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
:bro:id:`str_split`: :bro:type:`function`                                  Splits a string into substrings with the help of an index vector of cutting
                                                                           points.
:bro:id:`strcmp`: :bro:type:`function`                                     Lexicographically compares two strings.
:bro:id:`string_cat`: :bro:type:`function`                                 Concatenates all arguments into a single string.
:bro:id:`string_fill`: :bro:type:`function`                                Generates a string of a given size and fills it with repetitions of a source
                                                                           string.
:bro:id:`string_to_ascii_hex`: :bro:type:`function`                        Returns an ASCII hexadecimal representation of a string.
:bro:id:`strip`: :bro:type:`function`                                      Strips whitespace at both ends of a string.
:bro:id:`strstr`: :bro:type:`function`                                     Locates the first occurrence of one string in another.
:bro:id:`sub`: :bro:type:`function`                                        Substitutes a given replacement string for the first occurrence of a pattern
                                                                           in a given string.
:bro:id:`sub_bytes`: :bro:type:`function`                                  Get a substring from a string, given a starting position and length.
:bro:id:`subst_string`: :bro:type:`function`                               Substitutes each (non-overlapping) appearance of a string in another.
:bro:id:`to_lower`: :bro:type:`function`                                   Replaces all uppercase letters in a string with their lowercase counterpart.
:bro:id:`to_string_literal`: :bro:type:`function`                          Replaces non-printable characters in a string with escaped sequences.
:bro:id:`to_upper`: :bro:type:`function`                                   Replaces all lowercase letters in a string with their uppercase counterpart.
========================================================================== ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: cat_string_array

   :Type: :bro:type:`function` (a: :bro:type:`string_array`) : :bro:type:`string`
   :Attributes: :bro:attr:`&deprecated`

   Concatenates all elements in an array of strings.
   

   :a: The :bro:type:`string_array` (``table[count] of string``).
   

   :returns: The concatenation of all elements in *a*.
   
   .. bro:see:: cat cat_sep string_cat cat_string_array_n
                fmt
                join_string_vec join_string_array

.. bro:id:: cat_string_array_n

   :Type: :bro:type:`function` (a: :bro:type:`string_array`, start: :bro:type:`count`, end: :bro:type:`count`) : :bro:type:`string`
   :Attributes: :bro:attr:`&deprecated`

   Concatenates a specific range of elements in an array of strings.
   

   :a: The :bro:type:`string_array` (``table[count] of string``).
   

   :start: The array index of the first element of the range.
   

   :end: The array index of the last element of the range.
   

   :returns: The concatenation of the range *[start, end]* in *a*.
   
   .. bro:see:: cat string_cat cat_string_array
                fmt
                join_string_vec join_string_array

.. bro:id:: clean

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
   
   If the string does not yet have a trailing NUL, one is added internally.
   
   In contrast to :bro:id:`escape_string`, this encoding is *not* fully reversible.` 
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. bro:see:: to_string_literal escape_string

.. bro:id:: edit

   :Type: :bro:type:`function` (arg_s: :bro:type:`string`, arg_edit_char: :bro:type:`string`) : :bro:type:`string`

   Returns an edited version of a string that applies a special
   "backspace character" (usually ``\x08`` for backspace or ``\x7f`` for DEL).
   For example, ``edit("hello there", "e")`` returns ``"llo t"``.
   

   :arg_s: The string to edit.
   

   :arg_edit_char: A string of exactly one character that represents the
                  "backspace character". If it is longer than one character Bro
                  generates a run-time error and uses the first character in
                  the string.
   

   :returns: An edited version of *arg_s* where *arg_edit_char* triggers the
            deletion of the last character.
   
   .. bro:see:: clean
                to_string_literal
                escape_string
                strip

.. bro:id:: escape_string

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
   
   In contrast to :bro:id:`clean`, this encoding is fully reversible.` 
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. bro:see:: clean to_string_literal

.. bro:id:: find_all

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string_set`

   Finds all occurrences of a pattern in a string.
   

   :str: The string to inspect.
   

   :re: The pattern to look for in *str*.
   

   :returns: The set of strings in *str* that match *re*, or the empty set.
   
   .. bro:see: find_last strstr

.. bro:id:: find_last

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string`

   Finds the last occurrence of a pattern in a string. This function returns
   the match that starts at the largest index in the string, which is not
   necessarily the longest match.  For example, a pattern of ``/.*/`` will
   return the final character in the string.
   

   :str: The string to inspect.
   

   :re: The pattern to look for in *str*.
   

   :returns: The last string in *str* that matches *re*, or the empty string.
   
   .. bro:see: find_all strstr

.. bro:id:: gsub

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`, repl: :bro:type:`string`) : :bro:type:`string`

   Substitutes a given replacement string for all occurrences of a pattern
   in a given string.
   

   :str: The string to perform the substitution in.
   

   :re: The pattern being replaced with *repl*.
   

   :repl: The string that replaces *re*.
   

   :returns: A copy of *str* with all occurrences of *re* replaced with *repl*.
   
   .. bro:see:: sub subst_string

.. bro:id:: hexdump

   :Type: :bro:type:`function` (data_str: :bro:type:`string`) : :bro:type:`string`

   Returns a hex dump for given input data. The hex dump renders 16 bytes per
   line, with hex on the left and ASCII (where printable)
   on the right.
   

   :data_str: The string to dump in hex format.
   

   :returns: The hex dump of the given string.
   
   .. bro:see:: string_to_ascii_hex bytestring_to_hexstr
   
   .. note:: Based on Netdude's hex editor code.
   

.. bro:id:: is_ascii

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`bool`

   Determines whether a given string contains only ASCII characters.
   

   :str: The string to examine.
   

   :returns: False if any byte value of *str* is greater than 127, and true
            otherwise.
   
   .. bro:see:: to_upper to_lower

.. bro:id:: join_string_array

   :Type: :bro:type:`function` (sep: :bro:type:`string`, a: :bro:type:`string_array`) : :bro:type:`string`
   :Attributes: :bro:attr:`&deprecated`

   Joins all values in the given array of strings with a separator placed
   between each element.
   

   :sep: The separator to place between each element.
   

   :a: The :bro:type:`string_array` (``table[count] of string``).
   

   :returns: The concatenation of all elements in *a*, with *sep* placed
            between each element.
   
   .. bro:see:: cat cat_sep string_cat cat_string_array cat_string_array_n
                fmt
                join_string_vec

.. bro:id:: join_string_vec

   :Type: :bro:type:`function` (vec: :bro:type:`string_vec`, sep: :bro:type:`string`) : :bro:type:`string`

   Joins all values in the given vector of strings with a separator placed
   between each element.
   

   :sep: The separator to place between each element.
   

   :vec: The :bro:type:`string_vec` (``vector of string``).
   

   :returns: The concatenation of all elements in *vec*, with *sep* placed
            between each element.
   
   .. bro:see:: cat cat_sep string_cat cat_string_array cat_string_array_n
                fmt
                join_string_array

.. bro:id:: levenshtein_distance

   :Type: :bro:type:`function` (s1: :bro:type:`string`, s2: :bro:type:`string`) : :bro:type:`count`

   Calculates the Levenshtein distance between the two strings. See `Wikipedia
   <http://en.wikipedia.org/wiki/Levenshtein_distance>`__ for more information.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :returns: The Levenshtein distance of two strings as a count.
   

.. bro:id:: reverse

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string`

   Returns a reversed copy of the string
   

   :str: The string to reverse.
   

   :returns: A reversed copy of *str*
   

.. bro:id:: sort_string_array

   :Type: :bro:type:`function` (a: :bro:type:`string_array`) : :bro:type:`string_array`
   :Attributes: :bro:attr:`&deprecated`

   Sorts an array of strings.
   

   :a: The :bro:type:`string_array` (``table[count] of string``).
   

   :returns: A sorted copy of *a*.
   
   .. bro:see:: sort

.. bro:id:: split

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string_array`
   :Attributes: :bro:attr:`&deprecated`

   Splits a string into an array of strings according to a pattern.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each element corresponds to a substring
            in *str* separated by *re*.
   
   .. bro:see:: split1 split_all split_n str_split split_string1 split_string_all split_string_n str_split
   
   .. note:: The returned table starts at index 1. Note that conceptually the
             return value is meant to be a vector and this might change in the
             future.
   

.. bro:id:: split1

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string_array`
   :Attributes: :bro:attr:`&deprecated`

   Splits a string *once* into a two-element array of strings according to a
   pattern. This function is the same as :bro:id:`split`, but *str* is only
   split once (if possible) at the earliest position and an array of two strings
   is returned.
   

   :str: The string to split.
   

   :re: The pattern describing the separator to split *str* in two pieces.
   

   :returns: An array of strings with two elements in which the first represents
            the substring in *str* up to the first occurence of *re*, and the
            second everything after *re*. An array of one string is returned
            when *s* cannot be split.
   
   .. bro:see:: split split_all split_n str_split split_string split_string_all split_string_n str_split

.. bro:id:: split_all

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string_array`
   :Attributes: :bro:attr:`&deprecated`

   Splits a string into an array of strings according to a pattern. This
   function is the same as :bro:id:`split`, except that the separators are
   returned as well. For example, ``split_all("a-b--cd", /(\-)+/)`` returns
   ``{"a", "-", "b", "--", "cd"}``: odd-indexed elements do not match the
   pattern and even-indexed ones do.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each two successive elements correspond
            to a substring in *str* of the part not matching *re* (odd-indexed)
            and the part that matches *re* (even-indexed).
   
   .. bro:see:: split split1 split_n str_split split_string split_string1 split_string_n str_split

.. bro:id:: split_n

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`, incl_sep: :bro:type:`bool`, max_num_sep: :bro:type:`count`) : :bro:type:`string_array`
   :Attributes: :bro:attr:`&deprecated`

   Splits a string a given number of times into an array of strings according
   to a pattern. This function is similar to :bro:id:`split1` and
   :bro:id:`split_all`, but with customizable behavior with respect to
   including separators in the result and the number of times to split.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :incl_sep: A flag indicating whether to include the separator matches in the
             result (as in :bro:id:`split_all`).
   

   :max_num_sep: The number of times to split *str*.
   

   :returns: An array of strings where, if *incl_sep* is true, each two
            successive elements correspond to a substring in *str* of the part
            not matching *re* (odd-indexed) and the part that matches *re*
            (even-indexed).
   
   .. bro:see:: split split1 split_all str_split split_string split_string1 split_string_all str_split

.. bro:id:: split_string

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string_vec`

   Splits a string into an array of strings according to a pattern.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each element corresponds to a substring
            in *str* separated by *re*.
   
   .. bro:see:: split_string1 split_string_all split_string_n str_split
   

.. bro:id:: split_string1

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string_vec`

   Splits a string *once* into a two-element array of strings according to a
   pattern. This function is the same as :bro:id:`split_string`, but *str* is
   only split once (if possible) at the earliest position and an array of two
   strings is returned.
   

   :str: The string to split.
   

   :re: The pattern describing the separator to split *str* in two pieces.
   

   :returns: An array of strings with two elements in which the first represents
            the substring in *str* up to the first occurence of *re*, and the
            second everything after *re*. An array of one string is returned
            when *s* cannot be split.
   
   .. bro:see:: split_string split_string_all split_string_n str_split

.. bro:id:: split_string_all

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`) : :bro:type:`string_vec`

   Splits a string into an array of strings according to a pattern. This
   function is the same as :bro:id:`split_string`, except that the separators
   are returned as well. For example, ``split_string_all("a-b--cd", /(\-)+/)``
   returns ``{"a", "-", "b", "--", "cd"}``: odd-indexed elements do match the
   pattern and even-indexed ones do not.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each two successive elements correspond
            to a substring in *str* of the part not matching *re* (even-indexed)
            and the part that matches *re* (odd-indexed).
   
   .. bro:see:: split_string split_string1 split_string_n str_split

.. bro:id:: split_string_n

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`, incl_sep: :bro:type:`bool`, max_num_sep: :bro:type:`count`) : :bro:type:`string_vec`

   Splits a string a given number of times into an array of strings according
   to a pattern. This function is similar to :bro:id:`split_string1` and
   :bro:id:`split_string_all`, but with customizable behavior with respect to
   including separators in the result and the number of times to split.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :incl_sep: A flag indicating whether to include the separator matches in the
             result (as in :bro:id:`split_string_all`).
   

   :max_num_sep: The number of times to split *str*.
   

   :returns: An array of strings where, if *incl_sep* is true, each two
            successive elements correspond to a substring in *str* of the part
            not matching *re* (even-indexed) and the part that matches *re*
            (odd-indexed).
   
   .. bro:see:: split_string split_string1 split_string_all str_split

.. bro:id:: str_shell_escape

   :Type: :bro:type:`function` (source: :bro:type:`string`) : :bro:type:`string`

   Takes a string and escapes characters that would allow execution of
   commands at the shell level. Must be used before including strings in
   :bro:id:`system` or similar calls.
   

   :source: The string to escape.
   

   :returns: A shell-escaped version of *source*.
   
   .. bro:see:: system

.. bro:id:: str_smith_waterman

   :Type: :bro:type:`function` (s1: :bro:type:`string`, s2: :bro:type:`string`, params: :bro:type:`sw_params`) : :bro:type:`sw_substring_vec`

   Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
   See `Wikipedia <http://en.wikipedia.org/wiki/Smith%E2%80%93Waterman_algorithm>`__.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :params: Parameters for the Smith-Waterman algorithm.
   

   :returns: The result of the Smith-Waterman algorithm calculation.

.. bro:id:: str_split

   :Type: :bro:type:`function` (s: :bro:type:`string`, idx: :bro:type:`index_vec`) : :bro:type:`string_vec`

   Splits a string into substrings with the help of an index vector of cutting
   points.
   

   :s: The string to split.
   

   :idx: The index vector (``vector of count``) with the cutting points.
   

   :returns: A vector of strings.
   
   .. bro:see:: split split1 split_all split_n

.. bro:id:: strcmp

   :Type: :bro:type:`function` (s1: :bro:type:`string`, s2: :bro:type:`string`) : :bro:type:`int`

   Lexicographically compares two strings.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :returns: An integer greater than, equal to, or less than 0 according as
            *s1* is greater than, equal to, or less than *s2*.

.. bro:id:: string_cat

   :Type: :bro:type:`function` (...) : :bro:type:`string`

   Concatenates all arguments into a single string. The function takes a
   variable number of arguments of type string and stitches them together.
   

   :returns: The concatenation of all (string) arguments.
   
   .. bro:see:: cat cat_sep cat_string_array cat_string_array_n
                fmt
                join_string_vec join_string_array

.. bro:id:: string_fill

   :Type: :bro:type:`function` (len: :bro:type:`int`, source: :bro:type:`string`) : :bro:type:`string`

   Generates a string of a given size and fills it with repetitions of a source
   string.
   

   :len: The length of the output string.
   

   :source: The string to concatenate repeatedly until *len* has been reached.
   

   :returns: A string of length *len* filled with *source*.

.. bro:id:: string_to_ascii_hex

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`string`

   Returns an ASCII hexadecimal representation of a string.
   

   :s: The string to convert to hex.
   

   :returns: A copy of *s* where each byte is replaced with the corresponding
            hex nibble.

.. bro:id:: strip

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string`

   Strips whitespace at both ends of a string.
   

   :str: The string to strip the whitespace from.
   

   :returns: A copy of *str* with leading and trailing whitespace removed.
   
   .. bro:see:: sub gsub

.. bro:id:: strstr

   :Type: :bro:type:`function` (big: :bro:type:`string`, little: :bro:type:`string`) : :bro:type:`count`

   Locates the first occurrence of one string in another.
   

   :big: The string to look in.
   

   :little: The (smaller) string to find inside *big*.
   

   :returns: The location of *little* in *big*, or 0 if *little* is not found in
            *big*.
   
   .. bro:see:: find_all find_last

.. bro:id:: sub

   :Type: :bro:type:`function` (str: :bro:type:`string`, re: :bro:type:`pattern`, repl: :bro:type:`string`) : :bro:type:`string`

   Substitutes a given replacement string for the first occurrence of a pattern
   in a given string.
   

   :str: The string to perform the substitution in.
   

   :re: The pattern being replaced with *repl*.
   

   :repl: The string that replaces *re*.
   

   :returns: A copy of *str* with the first occurence of *re* replaced with
            *repl*.
   
   .. bro:see:: gsub subst_string

.. bro:id:: sub_bytes

   :Type: :bro:type:`function` (s: :bro:type:`string`, start: :bro:type:`count`, n: :bro:type:`int`) : :bro:type:`string`

   Get a substring from a string, given a starting position and length.
   

   :s: The string to obtain a substring from.
   

   :start: The starting position of the substring in *s*, where 1 is the first
          character. As a special case, 0 also represents the first character.
   

   :n: The number of characters to extract, beginning at *start*.
   

   :returns: A substring of *s* of length *n* from position *start*.

.. bro:id:: subst_string

   :Type: :bro:type:`function` (s: :bro:type:`string`, from: :bro:type:`string`, to: :bro:type:`string`) : :bro:type:`string`

   Substitutes each (non-overlapping) appearance of a string in another.
   

   :s: The string in which to perform the substitution.
   

   :from: The string to look for which is replaced with *to*.
   

   :to: The string that replaces all occurrences of *from* in *s*.
   

   :returns: A copy of *s* where each occurrence of *from* is replaced with *to*.
   
   .. bro:see:: sub gsub

.. bro:id:: to_lower

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string`

   Replaces all uppercase letters in a string with their lowercase counterpart.
   

   :str: The string to convert to lowercase letters.
   

   :returns: A copy of the given string with the uppercase letters (as indicated
            by ``isascii`` and ``isupper``) folded to lowercase
            (via ``tolower``).
   
   .. bro:see:: to_upper is_ascii

.. bro:id:: to_string_literal

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
       - ``'`` and ``""`` to ``\'`` and ``\"``, respectively.
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. bro:see:: clean escape_string

.. bro:id:: to_upper

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string`

   Replaces all lowercase letters in a string with their uppercase counterpart.
   

   :str: The string to convert to uppercase letters.
   

   :returns: A copy of the given string with the lowercase letters (as indicated
            by ``isascii`` and ``islower``) folded to uppercase
            (via ``toupper``).
   
   .. bro:see:: to_lower is_ascii


