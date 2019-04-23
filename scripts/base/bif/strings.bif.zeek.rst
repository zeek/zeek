:tocdepth: 3

base/bif/strings.bif.zeek
=========================
.. zeek:namespace:: GLOBAL

Definitions of built-in functions related to string processing and
manipulation.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
============================================================================= ============================================================================
:zeek:id:`cat_string_array`: :zeek:type:`function` :zeek:attr:`&deprecated`   Concatenates all elements in an array of strings.
:zeek:id:`cat_string_array_n`: :zeek:type:`function` :zeek:attr:`&deprecated` Concatenates a specific range of elements in an array of strings.
:zeek:id:`clean`: :zeek:type:`function`                                       Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`edit`: :zeek:type:`function`                                        Returns an edited version of a string that applies a special
                                                                              "backspace character" (usually ``\x08`` for backspace or ``\x7f`` for DEL).
:zeek:id:`escape_string`: :zeek:type:`function`                               Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`find_all`: :zeek:type:`function`                                    Finds all occurrences of a pattern in a string.
:zeek:id:`find_last`: :zeek:type:`function`                                   Finds the last occurrence of a pattern in a string.
:zeek:id:`gsub`: :zeek:type:`function`                                        Substitutes a given replacement string for all occurrences of a pattern
                                                                              in a given string.
:zeek:id:`hexdump`: :zeek:type:`function`                                     Returns a hex dump for given input data.
:zeek:id:`is_ascii`: :zeek:type:`function`                                    Determines whether a given string contains only ASCII characters.
:zeek:id:`join_string_array`: :zeek:type:`function` :zeek:attr:`&deprecated`  Joins all values in the given array of strings with a separator placed
                                                                              between each element.
:zeek:id:`join_string_vec`: :zeek:type:`function`                             Joins all values in the given vector of strings with a separator placed
                                                                              between each element.
:zeek:id:`levenshtein_distance`: :zeek:type:`function`                        Calculates the Levenshtein distance between the two strings.
:zeek:id:`lstrip`: :zeek:type:`function`                                      Removes all combinations of characters in the *chars* argument
                                                                              starting at the beginning of the string until first mismatch.
:zeek:id:`reverse`: :zeek:type:`function`                                     Returns a reversed copy of the string
:zeek:id:`rstrip`: :zeek:type:`function`                                      Removes all combinations of characters in the *chars* argument
                                                                              starting at the end of the string until first mismatch.
:zeek:id:`safe_shell_quote`: :zeek:type:`function`                            Takes a string and escapes characters that would allow execution of
                                                                              commands at the shell level.
:zeek:id:`sort_string_array`: :zeek:type:`function` :zeek:attr:`&deprecated`  Sorts an array of strings.
:zeek:id:`split`: :zeek:type:`function` :zeek:attr:`&deprecated`              Splits a string into an array of strings according to a pattern.
:zeek:id:`split1`: :zeek:type:`function` :zeek:attr:`&deprecated`             Splits a string *once* into a two-element array of strings according to a
                                                                              pattern.
:zeek:id:`split_all`: :zeek:type:`function` :zeek:attr:`&deprecated`          Splits a string into an array of strings according to a pattern.
:zeek:id:`split_n`: :zeek:type:`function` :zeek:attr:`&deprecated`            Splits a string a given number of times into an array of strings according
                                                                              to a pattern.
:zeek:id:`split_string`: :zeek:type:`function`                                Splits a string into an array of strings according to a pattern.
:zeek:id:`split_string1`: :zeek:type:`function`                               Splits a string *once* into a two-element array of strings according to a
                                                                              pattern.
:zeek:id:`split_string_all`: :zeek:type:`function`                            Splits a string into an array of strings according to a pattern.
:zeek:id:`split_string_n`: :zeek:type:`function`                              Splits a string a given number of times into an array of strings according
                                                                              to a pattern.
:zeek:id:`str_shell_escape`: :zeek:type:`function` :zeek:attr:`&deprecated`   Takes a string and escapes characters that would allow execution of
                                                                              commands at the shell level.
:zeek:id:`str_smith_waterman`: :zeek:type:`function`                          Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
:zeek:id:`str_split`: :zeek:type:`function`                                   Splits a string into substrings with the help of an index vector of cutting
                                                                              points.
:zeek:id:`strcmp`: :zeek:type:`function`                                      Lexicographically compares two strings.
:zeek:id:`string_cat`: :zeek:type:`function`                                  Concatenates all arguments into a single string.
:zeek:id:`string_fill`: :zeek:type:`function`                                 Generates a string of a given size and fills it with repetitions of a source
                                                                              string.
:zeek:id:`string_to_ascii_hex`: :zeek:type:`function`                         Returns an ASCII hexadecimal representation of a string.
:zeek:id:`strip`: :zeek:type:`function`                                       Strips whitespace at both ends of a string.
:zeek:id:`strstr`: :zeek:type:`function`                                      Locates the first occurrence of one string in another.
:zeek:id:`sub`: :zeek:type:`function`                                         Substitutes a given replacement string for the first occurrence of a pattern
                                                                              in a given string.
:zeek:id:`sub_bytes`: :zeek:type:`function`                                   Get a substring from a string, given a starting position and length.
:zeek:id:`subst_string`: :zeek:type:`function`                                Substitutes each (non-overlapping) appearance of a string in another.
:zeek:id:`to_lower`: :zeek:type:`function`                                    Replaces all uppercase letters in a string with their lowercase counterpart.
:zeek:id:`to_string_literal`: :zeek:type:`function`                           Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`to_upper`: :zeek:type:`function`                                    Replaces all lowercase letters in a string with their uppercase counterpart.
============================================================================= ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: cat_string_array

   :Type: :zeek:type:`function` (a: :zeek:type:`string_array`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&deprecated`

   Concatenates all elements in an array of strings.
   

   :a: The :zeek:type:`string_array` (``table[count] of string``).
   

   :returns: The concatenation of all elements in *a*.
   
   .. zeek:see:: cat cat_sep string_cat cat_string_array_n
                fmt
                join_string_vec join_string_array

.. zeek:id:: cat_string_array_n

   :Type: :zeek:type:`function` (a: :zeek:type:`string_array`, start: :zeek:type:`count`, end: :zeek:type:`count`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&deprecated`

   Concatenates a specific range of elements in an array of strings.
   

   :a: The :zeek:type:`string_array` (``table[count] of string``).
   

   :start: The array index of the first element of the range.
   

   :end: The array index of the last element of the range.
   

   :returns: The concatenation of the range *[start, end]* in *a*.
   
   .. zeek:see:: cat string_cat cat_string_array
                fmt
                join_string_vec join_string_array

.. zeek:id:: clean

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
   
   If the string does not yet have a trailing NUL, one is added internally.
   
   In contrast to :zeek:id:`escape_string`, this encoding is *not* fully reversible.`
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: to_string_literal escape_string

.. zeek:id:: edit

   :Type: :zeek:type:`function` (arg_s: :zeek:type:`string`, arg_edit_char: :zeek:type:`string`) : :zeek:type:`string`

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
   
   .. zeek:see:: clean
                to_string_literal
                escape_string
                strip

.. zeek:id:: escape_string

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
   
   In contrast to :zeek:id:`clean`, this encoding is fully reversible.`
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: clean to_string_literal

.. zeek:id:: find_all

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_set`

   Finds all occurrences of a pattern in a string.
   

   :str: The string to inspect.
   

   :re: The pattern to look for in *str*.
   

   :returns: The set of strings in *str* that match *re*, or the empty set.
   
   .. zeek:see: find_last strstr

.. zeek:id:: find_last

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string`

   Finds the last occurrence of a pattern in a string. This function returns
   the match that starts at the largest index in the string, which is not
   necessarily the longest match.  For example, a pattern of ``/.*/`` will
   return the final character in the string.
   

   :str: The string to inspect.
   

   :re: The pattern to look for in *str*.
   

   :returns: The last string in *str* that matches *re*, or the empty string.
   
   .. zeek:see: find_all strstr

.. zeek:id:: gsub

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, repl: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes a given replacement string for all occurrences of a pattern
   in a given string.
   

   :str: The string to perform the substitution in.
   

   :re: The pattern being replaced with *repl*.
   

   :repl: The string that replaces *re*.
   

   :returns: A copy of *str* with all occurrences of *re* replaced with *repl*.
   
   .. zeek:see:: sub subst_string

.. zeek:id:: hexdump

   :Type: :zeek:type:`function` (data_str: :zeek:type:`string`) : :zeek:type:`string`

   Returns a hex dump for given input data. The hex dump renders 16 bytes per
   line, with hex on the left and ASCII (where printable)
   on the right.
   

   :data_str: The string to dump in hex format.
   

   :returns: The hex dump of the given string.
   
   .. zeek:see:: string_to_ascii_hex bytestring_to_hexstr
   
   .. note:: Based on Netdude's hex editor code.
   

.. zeek:id:: is_ascii

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Determines whether a given string contains only ASCII characters.
   

   :str: The string to examine.
   

   :returns: False if any byte value of *str* is greater than 127, and true
            otherwise.
   
   .. zeek:see:: to_upper to_lower

.. zeek:id:: join_string_array

   :Type: :zeek:type:`function` (sep: :zeek:type:`string`, a: :zeek:type:`string_array`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&deprecated`

   Joins all values in the given array of strings with a separator placed
   between each element.
   

   :sep: The separator to place between each element.
   

   :a: The :zeek:type:`string_array` (``table[count] of string``).
   

   :returns: The concatenation of all elements in *a*, with *sep* placed
            between each element.
   
   .. zeek:see:: cat cat_sep string_cat cat_string_array cat_string_array_n
                fmt
                join_string_vec

.. zeek:id:: join_string_vec

   :Type: :zeek:type:`function` (vec: :zeek:type:`string_vec`, sep: :zeek:type:`string`) : :zeek:type:`string`

   Joins all values in the given vector of strings with a separator placed
   between each element.
   

   :sep: The separator to place between each element.
   

   :vec: The :zeek:type:`string_vec` (``vector of string``).
   

   :returns: The concatenation of all elements in *vec*, with *sep* placed
            between each element.
   
   .. zeek:see:: cat cat_sep string_cat cat_string_array cat_string_array_n
                fmt
                join_string_array

.. zeek:id:: levenshtein_distance

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`) : :zeek:type:`count`

   Calculates the Levenshtein distance between the two strings. See `Wikipedia
   <http://en.wikipedia.org/wiki/Levenshtein_distance>`__ for more information.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :returns: The Levenshtein distance of two strings as a count.
   

.. zeek:id:: lstrip

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, chars: :zeek:type:`string` :zeek:attr:`&default` = ``" \x09\x0a\x0d\x0b\x0c"`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Removes all combinations of characters in the *chars* argument
   starting at the beginning of the string until first mismatch.
   

   :str: The string to strip characters from.
   

   :chars: A string consisting of the characters to be removed.
          Defaults to all whitespace characters.
   

   :returns: A copy of *str* with the characters in *chars* removed from
            the beginning.
   
   .. zeek:see:: sub gsub strip rstrip

.. zeek:id:: reverse

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Returns a reversed copy of the string
   

   :str: The string to reverse.
   

   :returns: A reversed copy of *str*
   

.. zeek:id:: rstrip

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, chars: :zeek:type:`string` :zeek:attr:`&default` = ``" \x09\x0a\x0d\x0b\x0c"`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Removes all combinations of characters in the *chars* argument
   starting at the end of the string until first mismatch.
   

   :str: The string to strip characters from.
   

   :chars: A string consisting of the characters to be removed.
          Defaults to all whitespace characters.
   

   :returns: A copy of *str* with the characters in *chars* removed from
            the end.
   
   .. zeek:see:: sub gsub strip lstrip

.. zeek:id:: safe_shell_quote

   :Type: :zeek:type:`function` (source: :zeek:type:`string`) : :zeek:type:`string`

   Takes a string and escapes characters that would allow execution of
   commands at the shell level. Must be used before including strings in
   :zeek:id:`system` or similar calls.
   

   :source: The string to escape.
   

   :returns: A shell-escaped version of *source*.  Specifically, this
            backslash-escapes characters whose literal value is not otherwise
            preserved by enclosure in double-quotes (dollar-sign, backquote,
            backslash, and double-quote itself), and then encloses that
            backslash-escaped string in double-quotes to ultimately preserve
            the literal value of all input characters.
   
   .. zeek:see:: system safe_shell_quote

.. zeek:id:: sort_string_array

   :Type: :zeek:type:`function` (a: :zeek:type:`string_array`) : :zeek:type:`string_array`
   :Attributes: :zeek:attr:`&deprecated`

   Sorts an array of strings.
   

   :a: The :zeek:type:`string_array` (``table[count] of string``).
   

   :returns: A sorted copy of *a*.
   
   .. zeek:see:: sort

.. zeek:id:: split

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_array`
   :Attributes: :zeek:attr:`&deprecated`

   Splits a string into an array of strings according to a pattern.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each element corresponds to a substring
            in *str* separated by *re*.
   
   .. zeek:see:: split1 split_all split_n str_split split_string1 split_string_all split_string_n str_split
   
   .. note:: The returned table starts at index 1. Note that conceptually the
             return value is meant to be a vector and this might change in the
             future.
   

.. zeek:id:: split1

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_array`
   :Attributes: :zeek:attr:`&deprecated`

   Splits a string *once* into a two-element array of strings according to a
   pattern. This function is the same as :zeek:id:`split`, but *str* is only
   split once (if possible) at the earliest position and an array of two strings
   is returned.
   

   :str: The string to split.
   

   :re: The pattern describing the separator to split *str* in two pieces.
   

   :returns: An array of strings with two elements in which the first represents
            the substring in *str* up to the first occurence of *re*, and the
            second everything after *re*. An array of one string is returned
            when *s* cannot be split.
   
   .. zeek:see:: split split_all split_n str_split split_string split_string_all split_string_n str_split

.. zeek:id:: split_all

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_array`
   :Attributes: :zeek:attr:`&deprecated`

   Splits a string into an array of strings according to a pattern. This
   function is the same as :zeek:id:`split`, except that the separators are
   returned as well. For example, ``split_all("a-b--cd", /(\-)+/)`` returns
   ``{"a", "-", "b", "--", "cd"}``: odd-indexed elements do not match the
   pattern and even-indexed ones do.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each two successive elements correspond
            to a substring in *str* of the part not matching *re* (odd-indexed)
            and the part that matches *re* (even-indexed).
   
   .. zeek:see:: split split1 split_n str_split split_string split_string1 split_string_n str_split

.. zeek:id:: split_n

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, incl_sep: :zeek:type:`bool`, max_num_sep: :zeek:type:`count`) : :zeek:type:`string_array`
   :Attributes: :zeek:attr:`&deprecated`

   Splits a string a given number of times into an array of strings according
   to a pattern. This function is similar to :zeek:id:`split1` and
   :zeek:id:`split_all`, but with customizable behavior with respect to
   including separators in the result and the number of times to split.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :incl_sep: A flag indicating whether to include the separator matches in the
             result (as in :zeek:id:`split_all`).
   

   :max_num_sep: The number of times to split *str*.
   

   :returns: An array of strings where, if *incl_sep* is true, each two
            successive elements correspond to a substring in *str* of the part
            not matching *re* (odd-indexed) and the part that matches *re*
            (even-indexed).
   
   .. zeek:see:: split split1 split_all str_split split_string split_string1 split_string_all str_split

.. zeek:id:: split_string

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string into an array of strings according to a pattern.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each element corresponds to a substring
            in *str* separated by *re*.
   
   .. zeek:see:: split_string1 split_string_all split_string_n str_split
   

.. zeek:id:: split_string1

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string *once* into a two-element array of strings according to a
   pattern. This function is the same as :zeek:id:`split_string`, but *str* is
   only split once (if possible) at the earliest position and an array of two
   strings is returned.
   

   :str: The string to split.
   

   :re: The pattern describing the separator to split *str* in two pieces.
   

   :returns: An array of strings with two elements in which the first represents
            the substring in *str* up to the first occurence of *re*, and the
            second everything after *re*. An array of one string is returned
            when *s* cannot be split.
   
   .. zeek:see:: split_string split_string_all split_string_n str_split

.. zeek:id:: split_string_all

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string into an array of strings according to a pattern. This
   function is the same as :zeek:id:`split_string`, except that the separators
   are returned as well. For example, ``split_string_all("a-b--cd", /(\-)+/)``
   returns ``{"a", "-", "b", "--", "cd"}``: odd-indexed elements do match the
   pattern and even-indexed ones do not.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each two successive elements correspond
            to a substring in *str* of the part not matching *re* (even-indexed)
            and the part that matches *re* (odd-indexed).
   
   .. zeek:see:: split_string split_string1 split_string_n str_split

.. zeek:id:: split_string_n

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, incl_sep: :zeek:type:`bool`, max_num_sep: :zeek:type:`count`) : :zeek:type:`string_vec`

   Splits a string a given number of times into an array of strings according
   to a pattern. This function is similar to :zeek:id:`split_string1` and
   :zeek:id:`split_string_all`, but with customizable behavior with respect to
   including separators in the result and the number of times to split.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :incl_sep: A flag indicating whether to include the separator matches in the
             result (as in :zeek:id:`split_string_all`).
   

   :max_num_sep: The number of times to split *str*.
   

   :returns: An array of strings where, if *incl_sep* is true, each two
            successive elements correspond to a substring in *str* of the part
            not matching *re* (even-indexed) and the part that matches *re*
            (odd-indexed).
   
   .. zeek:see:: split_string split_string1 split_string_all str_split

.. zeek:id:: str_shell_escape

   :Type: :zeek:type:`function` (source: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&deprecated`

   Takes a string and escapes characters that would allow execution of
   commands at the shell level. Must be used before including strings in
   :zeek:id:`system` or similar calls.  This function is deprecated, use
   :zeek:see:`safe_shell_quote` as a replacement.  The difference is that
   :zeek:see:`safe_shell_quote` automatically returns a value that is
   wrapped in double-quotes, which is required to correctly and fully
   escape any characters that might be interpreted by the shell.
   

   :source: The string to escape.
   

   :returns: A shell-escaped version of *source*.
   
   .. zeek:see:: system safe_shell_quote

.. zeek:id:: str_smith_waterman

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`, params: :zeek:type:`sw_params`) : :zeek:type:`sw_substring_vec`

   Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
   See `Wikipedia <http://en.wikipedia.org/wiki/Smith%E2%80%93Waterman_algorithm>`__.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :params: Parameters for the Smith-Waterman algorithm.
   

   :returns: The result of the Smith-Waterman algorithm calculation.

.. zeek:id:: str_split

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, idx: :zeek:type:`index_vec`) : :zeek:type:`string_vec`

   Splits a string into substrings with the help of an index vector of cutting
   points.
   

   :s: The string to split.
   

   :idx: The index vector (``vector of count``) with the cutting points.
   

   :returns: A vector of strings.
   
   .. zeek:see:: split split1 split_all split_n

.. zeek:id:: strcmp

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`) : :zeek:type:`int`

   Lexicographically compares two strings.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :returns: An integer greater than, equal to, or less than 0 according as
            *s1* is greater than, equal to, or less than *s2*.

.. zeek:id:: string_cat

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Concatenates all arguments into a single string. The function takes a
   variable number of arguments of type string and stitches them together.
   

   :returns: The concatenation of all (string) arguments.
   
   .. zeek:see:: cat cat_sep cat_string_array cat_string_array_n
                fmt
                join_string_vec join_string_array

.. zeek:id:: string_fill

   :Type: :zeek:type:`function` (len: :zeek:type:`int`, source: :zeek:type:`string`) : :zeek:type:`string`

   Generates a string of a given size and fills it with repetitions of a source
   string.
   

   :len: The length of the output string.
   

   :source: The string to concatenate repeatedly until *len* has been reached.
   

   :returns: A string of length *len* filled with *source*.

.. zeek:id:: string_to_ascii_hex

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Returns an ASCII hexadecimal representation of a string.
   

   :s: The string to convert to hex.
   

   :returns: A copy of *s* where each byte is replaced with the corresponding
            hex nibble.

.. zeek:id:: strip

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Strips whitespace at both ends of a string.
   

   :str: The string to strip the whitespace from.
   

   :returns: A copy of *str* with leading and trailing whitespace removed.
   
   .. zeek:see:: sub gsub lstrip rstrip

.. zeek:id:: strstr

   :Type: :zeek:type:`function` (big: :zeek:type:`string`, little: :zeek:type:`string`) : :zeek:type:`count`

   Locates the first occurrence of one string in another.
   

   :big: The string to look in.
   

   :little: The (smaller) string to find inside *big*.
   

   :returns: The location of *little* in *big*, or 0 if *little* is not found in
            *big*.
   
   .. zeek:see:: find_all find_last

.. zeek:id:: sub

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, repl: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes a given replacement string for the first occurrence of a pattern
   in a given string.
   

   :str: The string to perform the substitution in.
   

   :re: The pattern being replaced with *repl*.
   

   :repl: The string that replaces *re*.
   

   :returns: A copy of *str* with the first occurence of *re* replaced with
            *repl*.
   
   .. zeek:see:: gsub subst_string

.. zeek:id:: sub_bytes

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, start: :zeek:type:`count`, n: :zeek:type:`int`) : :zeek:type:`string`

   Get a substring from a string, given a starting position and length.
   

   :s: The string to obtain a substring from.
   

   :start: The starting position of the substring in *s*, where 1 is the first
          character. As a special case, 0 also represents the first character.
   

   :n: The number of characters to extract, beginning at *start*.
   

   :returns: A substring of *s* of length *n* from position *start*.

.. zeek:id:: subst_string

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, from: :zeek:type:`string`, to: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes each (non-overlapping) appearance of a string in another.
   

   :s: The string in which to perform the substitution.
   

   :from: The string to look for which is replaced with *to*.
   

   :to: The string that replaces all occurrences of *from* in *s*.
   

   :returns: A copy of *s* where each occurrence of *from* is replaced with *to*.
   
   .. zeek:see:: sub gsub

.. zeek:id:: to_lower

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces all uppercase letters in a string with their lowercase counterpart.
   

   :str: The string to convert to lowercase letters.
   

   :returns: A copy of the given string with the uppercase letters (as indicated
            by ``isascii`` and ``isupper``) folded to lowercase
            (via ``tolower``).
   
   .. zeek:see:: to_upper is_ascii

.. zeek:id:: to_string_literal

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
       - ``'`` and ``""`` to ``\'`` and ``\"``, respectively.
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: clean escape_string

.. zeek:id:: to_upper

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces all lowercase letters in a string with their uppercase counterpart.
   

   :str: The string to convert to uppercase letters.
   

   :returns: A copy of the given string with the lowercase letters (as indicated
            by ``isascii`` and ``islower``) folded to uppercase
            (via ``toupper``).
   
   .. zeek:see:: to_lower is_ascii


