:tocdepth: 3

base/utils/patterns.zeek
========================
.. bro:namespace:: GLOBAL

Functions for creating and working with patterns.

:Namespace: GLOBAL

Summary
~~~~~~~
Types
#####
================================================== =
:bro:type:`PatternMatchResult`: :bro:type:`record` 
================================================== =

Functions
#########
============================================= =========================================================================
:bro:id:`match_pattern`: :bro:type:`function` Matches the given pattern against the given string, returning
                                              a :bro:type:`PatternMatchResult` record.
:bro:id:`set_to_regex`: :bro:type:`function`  Given a pattern as a string with two tildes (~~) contained in it, it will
                                              return a pattern with string set's elements OR'd together where the
                                              double-tilde was given (this function only works at or before init time).
============================================= =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: PatternMatchResult

   :Type: :bro:type:`record`

      matched: :bro:type:`bool`
         T if a match was found, F otherwise.

      str: :bro:type:`string`
         Portion of string that first matched.

      off: :bro:type:`count`
         1-based offset where match starts.


Functions
#########
.. bro:id:: match_pattern

   :Type: :bro:type:`function` (s: :bro:type:`string`, p: :bro:type:`pattern`) : :bro:type:`PatternMatchResult`

   Matches the given pattern against the given string, returning
   a :bro:type:`PatternMatchResult` record.
   For example: ``match_pattern("foobar", /o*[a-k]/)`` returns
   ``[matched=T, str=f, off=1]``,  because the *first* match is for
   zero o's followed by an [a-k], but ``match_pattern("foobar", /o+[a-k]/)``
   returns ``[matched=T, str=oob, off=2]``.
   

   :s: a string to match against.
   

   :p: a pattern to match.
   

   :returns: a record indicating the match status.

.. bro:id:: set_to_regex

   :Type: :bro:type:`function` (ss: :bro:type:`set` [:bro:type:`string`], pat: :bro:type:`string`) : :bro:type:`pattern`

   Given a pattern as a string with two tildes (~~) contained in it, it will
   return a pattern with string set's elements OR'd together where the
   double-tilde was given (this function only works at or before init time).
   

   :ss: a set of strings to OR together.
   

   :pat: the pattern containing a "~~"  in it.  If a literal backslash is
        included, it needs to be escaped with another backslash due to Bro's
        string parsing reducing it to a single backslash upon rendering.
   

   :returns: the input pattern with "~~" replaced by OR'd elements of input set.


