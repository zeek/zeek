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
====================================================== ==========================================================================================================
:zeek:id:`clean`: :zeek:type:`function`                Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`count_substr`: :zeek:type:`function`         Returns the number of times a substring occurs within a string
:zeek:id:`edit`: :zeek:type:`function`                 Returns an edited version of a string that applies a special
                                                       "backspace character" (usually ``\x08`` for backspace or ``\x7f`` for DEL).
:zeek:id:`ends_with`: :zeek:type:`function`            Returns whether a string ends with a substring.
:zeek:id:`escape_string`: :zeek:type:`function`        Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`find_all`: :zeek:type:`function`             Finds all occurrences of a pattern in a string.
:zeek:id:`find_all_ordered`: :zeek:type:`function`     Finds all occurrences of a pattern in a string.
:zeek:id:`find_first`: :zeek:type:`function`           Finds the first occurrence of a pattern in a string.
:zeek:id:`find_last`: :zeek:type:`function`            Finds the last occurrence of a pattern in a string.
:zeek:id:`find_str`: :zeek:type:`function`             Finds a string within another string, starting from the beginning.
:zeek:id:`gsub`: :zeek:type:`function`                 Substitutes a given replacement string for all occurrences of a pattern
                                                       in a given string.
:zeek:id:`hexdump`: :zeek:type:`function`              Returns a hex dump for given input data.
:zeek:id:`is_alnum`: :zeek:type:`function`             Returns whether a string consists entirely of alphanumeric characters.
:zeek:id:`is_alpha`: :zeek:type:`function`             Returns whether a string consists entirely of alphabetic characters.
:zeek:id:`is_ascii`: :zeek:type:`function`             Determines whether a given string contains only ASCII characters.
:zeek:id:`is_num`: :zeek:type:`function`               Returns whether a string consists entirely of digits.
:zeek:id:`join_string_set`: :zeek:type:`function`      Joins all values in the given set of strings with a separator placed
                                                       between each element.
:zeek:id:`join_string_vec`: :zeek:type:`function`      Joins all values in the given vector of strings with a separator placed
                                                       between each element.
:zeek:id:`levenshtein_distance`: :zeek:type:`function` Calculates the Levenshtein distance between the two strings.
:zeek:id:`ljust`: :zeek:type:`function`                Returns a left-justified version of the string, padded to a specific length
                                                       with a specified character.
:zeek:id:`lstrip`: :zeek:type:`function`               Removes all combinations of characters in the *chars* argument
                                                       starting at the beginning of the string until first mismatch.
:zeek:id:`remove_prefix`: :zeek:type:`function`        Similar to lstrip(), except does the removal repeatedly if the pattern repeats at the start of the string.
:zeek:id:`remove_suffix`: :zeek:type:`function`        Similar to rstrip(), except does the removal repeatedly if the pattern repeats at the end of the string.
:zeek:id:`reverse`: :zeek:type:`function`              Returns a reversed copy of the string
:zeek:id:`rfind_str`: :zeek:type:`function`            The same as :zeek:see:`find_str`, but returns the highest index matching
                                                       the substring instead of the smallest.
:zeek:id:`rjust`: :zeek:type:`function`                Returns a right-justified version of the string, padded to a specific length
                                                       with a specified character.
:zeek:id:`rstrip`: :zeek:type:`function`               Removes all combinations of characters in the *chars* argument
                                                       starting at the end of the string until first mismatch.
:zeek:id:`safe_shell_quote`: :zeek:type:`function`     Takes a string and escapes characters that would allow execution of
                                                       commands at the shell level.
:zeek:id:`split_string`: :zeek:type:`function`         Splits a string into an array of strings according to a pattern.
:zeek:id:`split_string1`: :zeek:type:`function`        Splits a string *once* into a two-element array of strings according to a
                                                       pattern.
:zeek:id:`split_string_all`: :zeek:type:`function`     Splits a string into an array of strings according to a pattern.
:zeek:id:`split_string_n`: :zeek:type:`function`       Splits a string a given number of times into an array of strings according
                                                       to a pattern.
:zeek:id:`starts_with`: :zeek:type:`function`          Returns whether a string starts with a substring.
:zeek:id:`str_smith_waterman`: :zeek:type:`function`   Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
:zeek:id:`str_split_indices`: :zeek:type:`function`    Splits a string into substrings with the help of an index vector of cutting
                                                       points.
:zeek:id:`strcmp`: :zeek:type:`function`               Lexicographically compares two strings.
:zeek:id:`string_cat`: :zeek:type:`function`           Concatenates all arguments into a single string.
:zeek:id:`string_fill`: :zeek:type:`function`          Generates a string of a given size and fills it with repetitions of a source
                                                       string.
:zeek:id:`string_to_ascii_hex`: :zeek:type:`function`  Returns an ASCII hexadecimal representation of a string.
:zeek:id:`strip`: :zeek:type:`function`                Strips whitespace at both ends of a string.
:zeek:id:`strstr`: :zeek:type:`function`               Locates the first occurrence of one string in another.
:zeek:id:`sub`: :zeek:type:`function`                  Substitutes a given replacement string for the first occurrence of a pattern
                                                       in a given string.
:zeek:id:`sub_bytes`: :zeek:type:`function`            Get a substring from a string, given a starting position and length.
:zeek:id:`subst_string`: :zeek:type:`function`         Substitutes each (non-overlapping) appearance of a string in another.
:zeek:id:`swap_case`: :zeek:type:`function`            Swaps the case of every alphabetic character in a string.
:zeek:id:`to_lower`: :zeek:type:`function`             Replaces all uppercase letters in a string with their lowercase counterpart.
:zeek:id:`to_string_literal`: :zeek:type:`function`    Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`to_title`: :zeek:type:`function`             Converts a string to Title Case.
:zeek:id:`to_upper`: :zeek:type:`function`             Replaces all lowercase letters in a string with their uppercase counterpart.
:zeek:id:`zfill`: :zeek:type:`function`                Returns a copy of a string filled on the left side with zeroes.
====================================================== ==========================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: clean
   :source-code: base/bif/strings.bif.zeek 281 281

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
   
   If the string does not yet have a trailing NUL, one is added internally.
   
   In contrast to :zeek:id:`escape_string`, this encoding is *not* fully reversible.`
   

   :param str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: to_string_literal escape_string

.. zeek:id:: count_substr
   :source-code: base/bif/strings.bif.zeek 528 528

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`count`

   Returns the number of times a substring occurs within a string
   

   :param str: The string to search in.

   :param substr: The string to search for.
   

   :returns: The number of times the substring occurred.
   

.. zeek:id:: edit
   :source-code: base/bif/strings.bif.zeek 82 82

   :Type: :zeek:type:`function` (arg_s: :zeek:type:`string`, arg_edit_char: :zeek:type:`string`) : :zeek:type:`string`

   Returns an edited version of a string that applies a special
   "backspace character" (usually ``\x08`` for backspace or ``\x7f`` for DEL).
   For example, ``edit("hello there", "e")`` returns ``"llo t"``.
   

   :param arg_s: The string to edit.
   

   :param arg_edit_char: A string of exactly one character that represents the
                  "backspace character". If it is longer than one character Zeek
                  generates a run-time error and uses the first character in
                  the string.
   

   :returns: An edited version of *arg_s* where *arg_edit_char* triggers the
            deletion of the last character.
   
   .. zeek:see:: clean
                to_string_literal
                escape_string
                strip

.. zeek:id:: ends_with
   :source-code: base/bif/strings.bif.zeek 579 579

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether a string ends with a substring.
   

.. zeek:id:: escape_string
   :source-code: base/bif/strings.bif.zeek 324 324

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
   
   In contrast to :zeek:id:`clean`, this encoding is fully reversible.`
   

   :param str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: clean to_string_literal

.. zeek:id:: find_all
   :source-code: base/bif/strings.bif.zeek 448 448

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, max_str_size: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`) : :zeek:type:`string_set`

   Finds all occurrences of a pattern in a string.
   

   :param str: The string to inspect.
   

   :param re: The pattern to look for in *str*.
   

   :param max_str_size: The maximum string size allowed as input. If set to -1, this will use the
                 :zeek:see:`max_find_all_string_length` global constant. If set to 0, this
                 check is disabled. If the length of `str` is greater than this size, an
                 empty set is returned.
   

   :returns: The set of strings in *str* that match *re*, or the empty set.
   
   .. zeek:see: find_all_ordered find_first find_last strstr

.. zeek:id:: find_all_ordered
   :source-code: base/bif/strings.bif.zeek 467 467

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, max_str_size: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`) : :zeek:type:`string_vec`

   Finds all occurrences of a pattern in a string.  The order in which
   occurrences are found is preserved and the return value may contain
   duplicate elements.
   

   :param str: The string to inspect.
   

   :param re: The pattern to look for in *str*.
   

   :param max_str_size: The maximum string size allowed as input. If set to -1, this will use the
                 :zeek:see:`max_find_all_string_length` global constant. If set to 0, this
                 check is disabled. If the length of `str` is greater than this size, an
                 empty set is returned.
   

   :returns: All strings in *str* that match *re*, or an empty vector.
   
   .. zeek:see: find_all find_first find_last strstr

.. zeek:id:: find_first
   :source-code: base/bif/strings.bif.zeek 494 494

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string`

   Finds the first occurrence of a pattern in a string.
   

   :param str: The string to inspect.
   

   :param re: The pattern to look for in *str*.
   

   :returns: The first string in *str* that matches *re*, or the empty string.
   
   .. zeek:see:: find_all find_all_ordered find_last strstr

.. zeek:id:: find_last
   :source-code: base/bif/strings.bif.zeek 482 482

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string`

   Finds the last occurrence of a pattern in a string. This function returns
   the match that starts at the largest index in the string, which is not
   necessarily the longest match.  For example, a pattern of ``/.*/`` will
   return the final character in the string.
   

   :param str: The string to inspect.
   

   :param re: The pattern to look for in *str*.
   

   :returns: The last string in *str* that matches *re*, or the empty string.
   
   .. zeek:see: find_all find_all_ordered strstr find_first

.. zeek:id:: find_str
   :source-code: base/bif/strings.bif.zeek 551 551

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`, start: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`, end: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`, case_sensitive: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`int`

   Finds a string within another string, starting from the beginning. This works
   by taking a substring within the provided indexes and searching for the sub
   argument. This means that ranges shorter than the string in the sub argument
   will always return a failure.
   

   :param str: The string to search in.

   :param substr: The string to search for.

   :param start: An optional position for the start of the substring.

   :param end: An optional position for the end of the substring. A value less than
        zero (such as the default -1) means a search until the end of the
        string.

   :param case_sensitive: Set to false to perform a case-insensitive search.
                   (default: T). Note that case-insensitive searches use the
                   ``tolower`` libc function, which is locale-sensitive.
   

   :returns: The position of the substring. Returns -1 if the string wasn't
            found. Prints an error if the starting position is after the ending
            position.

.. zeek:id:: gsub
   :source-code: base/bif/strings.bif.zeek 201 201

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, repl: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes a given replacement string for all occurrences of a pattern
   in a given string.
   

   :param str: The string to perform the substitution in.
   

   :param re: The pattern being replaced with *repl*.
   

   :param repl: The string that replaces *re*.
   

   :returns: A copy of *str* with all occurrences of *re* replaced with *repl*.
   
   .. zeek:see:: sub subst_string

.. zeek:id:: hexdump
   :source-code: base/bif/strings.bif.zeek 509 509

   :Type: :zeek:type:`function` (data_str: :zeek:type:`string`) : :zeek:type:`string`

   Returns a hex dump for given input data. The hex dump renders 16 bytes per
   line, with hex on the left and ASCII (where printable)
   on the right.
   

   :param data_str: The string to dump in hex format.
   

   :returns: The hex dump of the given string.
   
   .. zeek:see:: string_to_ascii_hex bytestring_to_hexstr
   
   .. note:: Based on Netdude's hex editor code.
   

.. zeek:id:: is_alnum
   :source-code: base/bif/strings.bif.zeek 597 597

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether a string consists entirely of alphanumeric characters.
   The empty string is not alphanumeric.
   

.. zeek:id:: is_alpha
   :source-code: base/bif/strings.bif.zeek 591 591

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether a string consists entirely of alphabetic characters.
   The empty string is not alphabetic.
   

.. zeek:id:: is_ascii
   :source-code: base/bif/strings.bif.zeek 308 308

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Determines whether a given string contains only ASCII characters.
   The empty string is ASCII.
   

   :param str: The string to examine.
   

   :returns: False if any byte value of *str* is greater than 127, and true
            otherwise.
   
   .. zeek:see:: to_upper to_lower

.. zeek:id:: is_num
   :source-code: base/bif/strings.bif.zeek 585 585

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether a string consists entirely of digits.
   The empty string is not numeric.
   

.. zeek:id:: join_string_set
   :source-code: base/bif/strings.bif.zeek 61 61

   :Type: :zeek:type:`function` (ss: :zeek:type:`string_set`, sep: :zeek:type:`string`) : :zeek:type:`string`

   Joins all values in the given set of strings with a separator placed
   between each element.
   

   :param ss: The :zeek:type:`string_set` (``set[string]``).
   

   :param sep: The separator to place between each element.
   

   :returns: The concatenation of all elements in *s*, with *sep* placed
            between each element.
   
   .. zeek:see:: cat cat_sep string_cat
                fmt
                join_string_vec

.. zeek:id:: join_string_vec
   :source-code: base/bif/strings.bif.zeek 45 45

   :Type: :zeek:type:`function` (vec: :zeek:type:`string_vec`, sep: :zeek:type:`string`) : :zeek:type:`string`

   Joins all values in the given vector of strings with a separator placed
   between each element.
   

   :param sep: The separator to place between each element.
   

   :param vec: The :zeek:type:`string_vec` (``vector of string``).
   

   :returns: The concatenation of all elements in *vec*, with *sep* placed
            between each element.
   
   .. zeek:see:: cat cat_sep string_cat
                fmt

.. zeek:id:: levenshtein_distance
   :source-code: base/bif/strings.bif.zeek 19 19

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`) : :zeek:type:`count`

   Calculates the Levenshtein distance between the two strings. See `Wikipedia
   <https://en.wikipedia.org/wiki/Levenshtein_distance>`__ for more information.
   

   :param s1: The first string.
   

   :param s2: The second string.
   

   :returns: The Levenshtein distance of two strings as a count.
   

.. zeek:id:: ljust
   :source-code: base/bif/strings.bif.zeek 613 613

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, width: :zeek:type:`count`, fill: :zeek:type:`string` :zeek:attr:`&default` = ``" "`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Returns a left-justified version of the string, padded to a specific length
   with a specified character.
   

   :param str: The string to left-justify.

   :param count: The length of the returned string. If this value is less than or
          equal to the length of str, a copy of str is returned.

   :param fill: The character used to fill in any extra characters in the resulting
         string. If a string longer than one character is passed, an error is
         reported. This defaults to the space character.
   

   :returns: A left-justified version of a string, padded with characters to a
            specific length.
   

.. zeek:id:: lstrip
   :source-code: base/bif/strings.bif.zeek 386 386

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, chars: :zeek:type:`string` :zeek:attr:`&default` = ``" \x09\x0a\x0d\x0b\x0c"`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Removes all combinations of characters in the *chars* argument
   starting at the beginning of the string until first mismatch.
   

   :param str: The string to strip characters from.
   

   :param chars: A string consisting of the characters to be removed.
          Defaults to all whitespace characters.
   

   :returns: A copy of *str* with the characters in *chars* removed from
            the beginning.
   
   .. zeek:see:: sub gsub strip rstrip

.. zeek:id:: remove_prefix
   :source-code: base/bif/strings.bif.zeek 658 658

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`string`

   Similar to lstrip(), except does the removal repeatedly if the pattern repeats at the start of the string.

.. zeek:id:: remove_suffix
   :source-code: base/bif/strings.bif.zeek 662 662

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`string`

   Similar to rstrip(), except does the removal repeatedly if the pattern repeats at the end of the string.

.. zeek:id:: reverse
   :source-code: base/bif/strings.bif.zeek 518 518

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Returns a reversed copy of the string
   

   :param str: The string to reverse.
   

   :returns: A reversed copy of *str*
   

.. zeek:id:: rfind_str
   :source-code: base/bif/strings.bif.zeek 569 569

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`, start: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`, end: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`, case_sensitive: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`int`

   The same as :zeek:see:`find_str`, but returns the highest index matching
   the substring instead of the smallest.
   

   :param str: The string to search in.

   :param substr: The string to search for.

   :param start: An optional position for the start of the substring.

   :param end: An optional position for the end of the substring. A value less than
        zero (such as the default -1) means a search from the end of the string.

   :param case_sensitive: Set to false to perform a case-insensitive search.
                   (default: T). Note that case-insensitive searches use the
                   ``tolower`` libc function, which is locale-sensitive.
   

   :returns: The position of the substring. Returns -1 if the string wasn't
            found. Prints an error if the starting position is after the ending
            position.

.. zeek:id:: rjust
   :source-code: base/bif/strings.bif.zeek 631 631

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, width: :zeek:type:`count`, fill: :zeek:type:`string` :zeek:attr:`&default` = ``" "`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Returns a right-justified version of the string, padded to a specific length
   with a specified character.
   

   :param str: The string to right-justify.

   :param count: The length of the returned string. If this value is less than or
          equal to the length of str, a copy of str is returned.

   :param fill: The character used to fill in any extra characters in the resulting
         string. If a string longer than one character is passed, an error is
         reported. This defaults to the space character.
   

   :returns: A right-justified version of a string, padded with characters to a
            specific length.
   

.. zeek:id:: rstrip
   :source-code: base/bif/strings.bif.zeek 401 401

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, chars: :zeek:type:`string` :zeek:attr:`&default` = ``" \x09\x0a\x0d\x0b\x0c"`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Removes all combinations of characters in the *chars* argument
   starting at the end of the string until first mismatch.
   

   :param str: The string to strip characters from.
   

   :param chars: A string consisting of the characters to be removed.
          Defaults to all whitespace characters.
   

   :returns: A copy of *str* with the characters in *chars* removed from
            the end.
   
   .. zeek:see:: sub gsub strip lstrip

.. zeek:id:: safe_shell_quote
   :source-code: base/bif/strings.bif.zeek 429 429

   :Type: :zeek:type:`function` (source: :zeek:type:`string`) : :zeek:type:`string`

   Takes a string and escapes characters that would allow execution of
   commands at the shell level. Must be used before including strings in
   :zeek:id:`system` or similar calls.
   

   :param source: The string to escape.
   

   :returns: A shell-escaped version of *source*.  Specifically, this
            backslash-escapes characters whose literal value is not otherwise
            preserved by enclosure in double-quotes (dollar-sign, backquote,
            backslash, and double-quote itself), and then encloses that
            backslash-escaped string in double-quotes to ultimately preserve
            the literal value of all input characters.
   
   .. zeek:see:: system safe_shell_quote

.. zeek:id:: split_string
   :source-code: base/bif/strings.bif.zeek 111 111

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string into an array of strings according to a pattern.
   

   :param str: The string to split.
   

   :param re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each element corresponds to a substring
            in *str* separated by *re*.
   
   .. zeek:see:: split_string1 split_string_all split_string_n
   

.. zeek:id:: split_string1
   :source-code: base/bif/strings.bif.zeek 129 129

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string *once* into a two-element array of strings according to a
   pattern. This function is the same as :zeek:id:`split_string`, but *str* is
   only split once (if possible) at the earliest position and an array of two
   strings is returned.
   

   :param str: The string to split.
   

   :param re: The pattern describing the separator to split *str* in two pieces.
   

   :returns: An array of strings with two elements in which the first represents
            the substring in *str* up to the first occurrence of *re*, and the
            second everything after *re*. An array of one string is returned
            when *s* cannot be split.
   
   .. zeek:see:: split_string split_string_all split_string_n

.. zeek:id:: split_string_all
   :source-code: base/bif/strings.bif.zeek 147 147

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string into an array of strings according to a pattern. This
   function is the same as :zeek:id:`split_string`, except that the separators
   are returned as well. For example, ``split_string_all("a-b--cd", /(\-)+/)``
   returns ``{"a", "-", "b", "--", "cd"}``: odd-indexed elements do match the
   pattern and even-indexed ones do not.
   

   :param str: The string to split.
   

   :param re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each two successive elements correspond
            to a substring in *str* of the part not matching *re* (even-indexed)
            and the part that matches *re* (odd-indexed).
   
   .. zeek:see:: split_string split_string1 split_string_n

.. zeek:id:: split_string_n
   :source-code: base/bif/strings.bif.zeek 170 170

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, incl_sep: :zeek:type:`bool`, max_num_sep: :zeek:type:`count`) : :zeek:type:`string_vec`

   Splits a string a given number of times into an array of strings according
   to a pattern. This function is similar to :zeek:id:`split_string1` and
   :zeek:id:`split_string_all`, but with customizable behavior with respect to
   including separators in the result and the number of times to split.
   

   :param str: The string to split.
   

   :param re: The pattern describing the element separator in *str*.
   

   :param incl_sep: A flag indicating whether to include the separator matches in the
             result (as in :zeek:id:`split_string_all`).
   

   :param max_num_sep: The number of times to split *str*.
   

   :returns: An array of strings where, if *incl_sep* is true, each two
            successive elements correspond to a substring in *str* of the part
            not matching *re* (even-indexed) and the part that matches *re*
            (odd-indexed).
   
   .. zeek:see:: split_string split_string1 split_string_all

.. zeek:id:: starts_with
   :source-code: base/bif/strings.bif.zeek 574 574

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether a string starts with a substring.
   

.. zeek:id:: str_smith_waterman
   :source-code: base/bif/strings.bif.zeek 346 346

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`, params: :zeek:type:`sw_params`) : :zeek:type:`sw_substring_vec`

   Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
   See `Wikipedia <https://en.wikipedia.org/wiki/Smith%E2%80%93Waterman_algorithm>`__.
   

   :param s1: The first string.
   

   :param s2: The second string.
   

   :param params: Parameters for the Smith-Waterman algorithm.
   

   :returns: The result of the Smith-Waterman algorithm calculation.

.. zeek:id:: str_split_indices
   :source-code: base/bif/strings.bif.zeek 359 359

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, idx: :zeek:type:`index_vec`) : :zeek:type:`string_vec`

   Splits a string into substrings with the help of an index vector of cutting
   points.
   

   :param s: The string to split.
   

   :param idx: The index vector (``vector of count``) with the cutting points
   

   :returns: A zero-indexed vector of strings.
   
   .. zeek:see:: split_string split_string1 split_string_all split_string_n

.. zeek:id:: strcmp
   :source-code: base/bif/strings.bif.zeek 213 213

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`) : :zeek:type:`int`

   Lexicographically compares two strings.
   

   :param s1: The first string.
   

   :param s2: The second string.
   

   :returns: An integer greater than, equal to, or less than 0 according as
            *s1* is greater than, equal to, or less than *s2*.

.. zeek:id:: string_cat
   :source-code: base/bif/strings.bif.zeek 30 30

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Concatenates all arguments into a single string. The function takes a
   variable number of arguments of type string and stitches them together.
   

   :returns: The concatenation of all (string) arguments.
   
   .. zeek:see:: cat cat_sep
                fmt
                join_string_vec

.. zeek:id:: string_fill
   :source-code: base/bif/strings.bif.zeek 412 412

   :Type: :zeek:type:`function` (len: :zeek:type:`int`, source: :zeek:type:`string`) : :zeek:type:`string`

   Generates a string of a given size and fills it with repetitions of a source
   string.
   

   :param len: The length of the output string.
   

   :param source: The string to concatenate repeatedly until *len* has been reached.
   

   :returns: A string of length *len* filled with *source*.

.. zeek:id:: string_to_ascii_hex
   :source-code: base/bif/strings.bif.zeek 333 333

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Returns an ASCII hexadecimal representation of a string.
   

   :param s: The string to convert to hex.
   

   :returns: A copy of *s* where each byte is replaced with the corresponding
            hex nibble.

.. zeek:id:: strip
   :source-code: base/bif/strings.bif.zeek 369 369

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Strips whitespace at both ends of a string.
   

   :param str: The string to strip the whitespace from.
   

   :returns: A copy of *str* with leading and trailing whitespace removed.
   
   .. zeek:see:: sub gsub lstrip rstrip

.. zeek:id:: strstr
   :source-code: base/bif/strings.bif.zeek 226 226

   :Type: :zeek:type:`function` (big: :zeek:type:`string`, little: :zeek:type:`string`) : :zeek:type:`count`

   Locates the first occurrence of one string in another.
   

   :param big: The string to look in.
   

   :param little: The (smaller) string to find inside *big*.
   

   :returns: The location of *little* in *big*, or 0 if *little* is not found in
            *big*.
   
   .. zeek:see:: find_all find_first find_last

.. zeek:id:: sub
   :source-code: base/bif/strings.bif.zeek 186 186

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, repl: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes a given replacement string for the first occurrence of a pattern
   in a given string.
   

   :param str: The string to perform the substitution in.
   

   :param re: The pattern being replaced with *repl*.
   

   :param repl: The string that replaces *re*.
   

   :returns: A copy of *str* with the first occurrence of *re* replaced with
            *repl*.
   
   .. zeek:see:: gsub subst_string

.. zeek:id:: sub_bytes
   :source-code: base/bif/strings.bif.zeek 95 95

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, start: :zeek:type:`count`, n: :zeek:type:`int`) : :zeek:type:`string`

   Get a substring from a string, given a starting position and length.
   

   :param s: The string to obtain a substring from.
   

   :param start: The starting position of the substring in *s*, where 1 is the first
          character. As a special case, 0 also represents the first character.
   

   :param n: The number of characters to extract, beginning at *start*.
   

   :returns: A substring of *s* of length *n* from position *start*.

.. zeek:id:: subst_string
   :source-code: base/bif/strings.bif.zeek 240 240

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, from: :zeek:type:`string`, to: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes each (non-overlapping) appearance of a string in another.
   

   :param s: The string in which to perform the substitution.
   

   :param from: The string to look for which is replaced with *to*.
   

   :param to: The string that replaces all occurrences of *from* in *s*.
   

   :returns: A copy of *s* where each occurrence of *from* is replaced with *to*.
   
   .. zeek:see:: sub gsub

.. zeek:id:: swap_case
   :source-code: base/bif/strings.bif.zeek 640 640

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Swaps the case of every alphabetic character in a string. For example, the string "aBc" be returned as "AbC".
   

   :param str: The string to swap cases in.
   

   :returns: A copy of the str with the case of each character swapped.
   

.. zeek:id:: to_lower
   :source-code: base/bif/strings.bif.zeek 252 252

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces all uppercase letters in a string with their lowercase counterpart.
   

   :param str: The string to convert to lowercase letters.
   

   :returns: A copy of the given string with the uppercase letters (as indicated
            by ``isascii`` and ``isupper``) folded to lowercase
            (via ``tolower``).
   
   .. zeek:see:: to_upper is_ascii

.. zeek:id:: to_string_literal
   :source-code: base/bif/strings.bif.zeek 296 296

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
       - ``'`` and ``""`` to ``\'`` and ``\"``, respectively.
   

   :param str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: clean escape_string

.. zeek:id:: to_title
   :source-code: base/bif/strings.bif.zeek 650 650

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Converts a string to Title Case. This changes the first character of each sequence of non-space characters
   in the string to be capitalized. See https://docs.python.org/3/library/stdtypes.html#str.title for more info.
   

   :param str: The string to convert.
   

   :returns: A title-cased version of the string.
   

.. zeek:id:: to_upper
   :source-code: base/bif/strings.bif.zeek 264 264

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces all lowercase letters in a string with their uppercase counterpart.
   

   :param str: The string to convert to uppercase letters.
   

   :returns: A copy of the given string with the lowercase letters (as indicated
            by ``isascii`` and ``islower``) folded to uppercase
            (via ``toupper``).
   
   .. zeek:see:: to_lower is_ascii

.. zeek:id:: zfill
   :source-code: base/bif/strings.bif.zeek 654 654

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, width: :zeek:type:`count`) : :zeek:type:`string`

   Returns a copy of a string filled on the left side with zeroes. This is effectively rjust(str, width, "0").


