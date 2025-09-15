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
                                                double-tilde was given.
=============================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: PatternMatchResult
   :source-code: base/utils/patterns.zeek 37 44

   :Type: :zeek:type:`record`


   .. zeek:field:: matched :zeek:type:`bool`

      T if a match was found, F otherwise.


   .. zeek:field:: str :zeek:type:`string`

      Portion of string that first matched.


   .. zeek:field:: off :zeek:type:`count`

      1-based offset where match starts.



Functions
#########
.. zeek:id:: match_pattern
   :source-code: base/utils/patterns.zeek 58 67

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, p: :zeek:type:`pattern`) : :zeek:type:`PatternMatchResult`

   Matches the given pattern against the given string, returning
   a :zeek:type:`PatternMatchResult` record.
   For example: ``match_pattern("foobar", /o*[a-k]/)`` returns
   ``[matched=T, str=f, off=1]``,  because the *first* match is for
   zero o's followed by an [a-k], but ``match_pattern("foobar", /o+[a-k]/)``
   returns ``[matched=T, str=oob, off=2]``.
   

   :param s: a string to match against.
   

   :param p: a pattern to match.
   

   :returns: a record indicating the match status.

.. zeek:id:: set_to_regex
   :source-code: base/utils/patterns.zeek 23 35

   :Type: :zeek:type:`function` (ss: :zeek:type:`set` [:zeek:type:`string`], pat: :zeek:type:`string`) : :zeek:type:`pattern`

   Given a pattern as a string with two tildes (~~) contained in it, it will
   return a pattern with string set's elements OR'd together where the
   double-tilde was given.  Examples:
   
     .. code-block:: zeek
   
       global r1 = set_to_regex(set("a", "b", "c"), "~~");
       # r1 = /^?(a|b|c)$?/
       global r2 = set_to_regex(set("a.com", "b.com", "c.com"), "\\.(~~)");
       # r2 = /^?(\.(a\.com|b\.com|c\.com))$?/
   

   :param ss: a set of strings to OR together.
   

   :param pat: the pattern containing a "~~"  in it.  If a literal backslash is
        included, it needs to be escaped with another backslash due to Zeek's
        string parsing reducing it to a single backslash upon rendering.
   

   :returns: the input pattern with "~~" replaced by OR'd elements of input set.


