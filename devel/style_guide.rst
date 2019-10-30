============================
Coding Style and Conventions
============================

Historical Context
==================

The Zeek codebase is quite old as code goes, with the original code being
written in 1995. Some of the internal container types date from around 1987.
This means that a large portion of it was written before a lot of modern C++
existed. As such, a lot of the early design decisions were made in that
context. This guide strives to suggest modern techniques where possible, even
when the existing code doesn't follow it to the letter. All new code should
follow this guide. Old code should be updated to follow this guide when it is
modified.

The base formatting for all Zeek C++ code, including C++ code inside BIF files,
follows the `Whitesmiths coding style
<https://en.wikipedia.org/wiki/Indentation_style#Whitesmiths_style>`_

Whitespace
==========

Tabs vs. Spaces
---------------

Use tabs for indentation and spaces for alignment. An example for alignment is
below.

.. sourcecode:: c++

  >   void FunctionWithALongName(int argument1,
  >   ...........................int argument2)
  >   >   {
  >   >   if ( argument1 == 1 ||
  >   >   .....argument2 == 2 )
  >   >   >   {
  >   >   >   DoSomething();
  >   >   >   DoSomethingMore();
  >   >   >   }
  >   >   }
  }

Tabs (represented by ``>``) are used to match indentation levels, and then then
spaces (represented by ``.`` in the cases where they're used for alignment) are
used to match a particular column of the line above it.

Conditional Expressions
-----------------------

Spaces should exist inside the outer parentheses for all control statements
(conditional expressions), but not function calls. A space should also follow
the keyword. For example:

.. sourcecode:: c++

  if ( condition )
	{
	}

  SomeFunction(arg1);

Logical not-operator (!)
------------------------

A space should exist after any not-operator. For example:

.. sourcecode:: c++

  if ( ! condition )
	{
	}

File Naming
===========

Header files should always use the ``.h`` extension. Implementation files
should always use the ``.cc`` extension.

Include Guards
==============

All headers should start with a ``#pragma once`` line to guard against
duplicate includes. Avoid using ``#ifndef``/``#define`` include guards.

Braces
======

For multi-line blocks, braces should start on the line after the construct.
Single-line blocks can remove the braces. For single-line function definitions
the braces can be on the same line as the function definition, with a tab
between the close of the function definition and the opening brace.

Multi-line Blocks
-----------------

.. sourcecode:: c++

  if ( true )
	{
	DoSomething();
	DoSomethingElse();
	}

Single-line Functions
---------------------

.. sourcecode:: c++

  bool Foo()	{ return false; }

Note that for single-line functions there should be a tab between the closing
``)`` and the opening ``{``.

Function and Variable Naming
============================

Type names (classes, enums, structs, etc) and function names should always be
``CamelCase``. Variable names, including member variables, should always be
``snake_case``. Prefer using more descriptive variable names, except for
counter variables.

Including Files
===============

Include files in both headers and implementation files should be ordered as
follows:

- C includes such as ``<unistd.h>``
- C++ includes such as ``<string>`` and ``<vector>``
- Local include headers from Zeek

Futher conventions include:

- Prefer to use the C++ version of headers rather than the C Standard version
  (when writing C++, of course).  E.g. use ``<cstdio>`` over ``<stdio.h>``.

- Use angle braces around the file name for anything not coming directly from
  the Zeek code base, e.g. ``<string>``. This includes any system headers, any
  external libraries, and anything that can be referring to a file outside the
  code distribution, even if typically it does refer to a file within the Zeek
  source tree because it's embedded for convenience (e.g. Broker/CAF).

- Use quotes around the file name for anything that always comes from the Zeek
  code base.  E.g. ``"Val.h"``

- Use forward declarations instead of including whenever possible.

Commenting
==========

Functions inside of header files should include doxygen-style comments,
including documentation for all parameters and return values. Implementation of
those methods in ``.cc`` files do not need to include the comment.  Example:

.. sourcecode:: c++

     /**
      * Recursively searches all (direct or indirect) childs of the
      * analyzer for an analyzer with a specific ID.
      *
      * @param id The analyzer id to search. This is the ID that GetID()
      * returns.
      *
      * @return The analyzer, or null if not found.
      */
     virtual Analyzer* FindChild(ID id);

Non-obvious algorithms should include comments about what the code is doing to
aid in later maintenance. Avoid writing comments for code where it is obvious
what that code is doing.

Pointers and References
=======================

Pointer and reference characters should associate with a type name rather than
the variable identifier. For example, use ``int* var`` and not ``int *var``.

Class Member Visibility/Ordering
================================

- Use the ordering ``public`` -> ``protected`` -> ``private`` in class
  definitions for members.

- If the class includes ``friend`` methods, list those at the start of the
  class prior to the `public` block.

- Within each visibility block, use the following ordering for members:

    - Static member functions
    - Non-static member functions
    - Static member variables
    - Non-static member variables

- Attempt to order member variables to avoid the compiler adding padding
  between them and bloating the size of the objects.

Language Support and Preferences
================================

Zeek may use C++ features up to and including those supported by the C++17
standard.

Exceptions
----------

Avoid using exceptions for error handling. The primary reason to avoid them is
that it makes error handling more difficult to reason about. Due to the nature
of the reference counting in the Zeek code, exceptions will often cause the
counting to be invalid unless handled very carefully.

Casting
-------

Use C++-style casting (``static_cast``, ``dynamic_cast``, ``reinterpret_cast``,
``const_cast``) instead of bare C-style casts.

Strings
-------

One artifact of the long life of this Zeek code is that a large number of the
strings created internally are plain ``char*`` values.  For new code, prefer
using ``std::string`` or ``std::string_view`` instead.

Explicit Constructors
---------------------

Single-argument constructors should be marked ``explicit`` to aid in
type-checking.

Using Namespaces
----------------

Source files (``*.cc``) may set up any namespace imports/aliases they find
convenient at any scope, including file scope.  For example, they may choose to
do ``using namespace std``.

Header files (``*.h``) should avoid, at file scope, anything that alters
namespaces or the name lookup process since it's usually not desirable for the
inclusion of a header to have those side effects.  E.g. don't do things like
``using namespace std`` in a header file.  However, it's acceptable to do this
inside function scopes should the implementation be defined in the header file.

Global Namespace
----------------

Another artifact of the old Zeek code is that a large amount of variables,
functions, and constants are defined in the global namespace and then
``extern``'d when needed in other places. Avoid adding any more to the global
namespace when possible. Prefer using constructs like the Singleton pattern or
static class members instead.

Function Parameter Passing
--------------------------

Follow the typical C++ best practices for parameter passing. Avoid passing
large objects by value, except in cases where the function can use move
semantics and the caller can use ``std::move``. For objects that will not be
modified by the function, pass by const-reference. For objects that may be
modified by the function, prefer making the argument a pointer instead of a
reference.

Default Member Variable Initialization
--------------------------------------

In new code, prefer using default initialization to set the values of member
variables when they are defined in the header. Override the values in
constructors only when necessary. For older code, use constructor
initialization for consistency.
