:tocdepth: 3

base/utils/patterns.zeek
========================
.. zeek:namespace:: GLOBAL

Functions for creating and working with patterns.

:Namespace: GLOBAL

Summary
~~~~~~~
Types
#####
==================================================== =
:zeek:type:`PatternMatchResult`: :zeek:type:`record` 
==================================================== =

Functions
#########
=============================================== =========================================================================
:zeek:id:`match_pattern`: :zeek:type:`function` Matches the given pattern against the given string, returning
                                                a :zeek:type:`PatternMatchResult` record.
:zeek:id:`set_to_regex`: :zeek:type:`function`  Given a pattern as a string with two tildes (~~) contained in it, it will
                                                return a pattern with string set's elements OR'd together where the
                                                double-tilde was given (this function only works at or before init time).
=============================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: PatternMatchResult

   :Type: :zeek:type:`record`

      matched: :zeek:type:`bool`
         T if a match was found, F otherwise.

      str: :zeek:type:`string`
         Portion of string that first matched.

      off: :zeek:type:`count`
         1-based offset where match starts.


Functions
#########
.. zeek:id:: match_pattern

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, p: :zeek:type:`pattern`) : :zeek:type:`PatternMatchResult`

   Matches the given pattern against the given string, returning
   a :zeek:type:`PatternMatchResult` record.
   For example: ``match_pattern("foobar", /o*[a-k]/)`` returns
   ``[matched=T, str=f, off=1]``,  because the *first* match is for
   zero o's followed by an [a-k], but ``match_pattern("foobar", /o+[a-k]/)``
   returns ``[matched=T, str=oob, off=2]``.
   

   :s: a string to match against.
   

   :p: a pattern to match.
   

   :returns: a record indicating the match status.

.. zeek:id:: set_to_regex

   :Type: :zeek:type:`function` (ss: :zeek:type:`set` [:zeek:type:`string`], pat: :zeek:type:`string`) : :zeek:type:`pattern`

   Given a pattern as a string with two tildes (~~) contained in it, it will
   return a pattern with string set's elements OR'd together where the
   double-tilde was given (this function only works at or before init time).
   

   :ss: a set of strings to OR together.
   

   :pat: the pattern containing a "~~"  in it.  If a literal backslash is
        included, it needs to be escaped with another backslash due to Zeek's
        string parsing reducing it to a single backslash upon rendering.
   

   :returns: the input pattern with "~~" replaced by OR'd elements of input set.


