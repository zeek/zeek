Zeek Coding Style and Development Guide
=======================================

Historical Context
------------------

The Zeek codebase is quite old as code goes, with the original code being written in 1995. This means that a large portion of it was written before a lot of modern C++ existed. As such, a lot of the early design decisions were made in that context. This guide strives to suggest modern techniques where possible, even when the existing code doesn't follow it to the letter. All new code should follow this guide. Old code should be updated to follow this guide when it is modified. 

Coding conventions and style guide
----------------------------------

Basic Formatting and Indentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The base formatting for all Zeek C++ code, including C++ code inside BIF files, follows the Whitesmith coding style (https://en.wikipedia.org/wiki/Indentation_style#Whitesmiths_style).

Tabs vs. Spaces
^^^^^^^^^^^^^^^

Use tabs for indentation and spaces for alignment.

File naming
^^^^^^^^^^^

Header files should always use the `.h` extension. Implementation files should always use the `.cc` extension.

Include guards
^^^^^^^^^^^^^^

All headers should have an `#infdef`/`#define` include guard at the start of it to avoid duplicate includes. Do not use `#pragma once`.

Braces
^^^^^^

For multi-line blocks, braces should start on the line after the construct. Single-line blocks can remove the braces. For single-line function definitions the braces can be on the same line as the function definition, with a tab between the close of the function definition and the opening brace.

Multi-line blocks
*****************

::

  if ( true )
	{
	DoSomething();
	DoSomethingElse();
	}

Single-line functions
*********************

::

  bool Foo()	{ return false; }


Function and variable naming
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Type names (classes, enums, structs, etc) and function names should always be `CamelCase`. Variable names, including member variables, should always be `snake_case`. Prefer using more descriptive variable names, except for counter variables.

Include files
^^^^^^^^^^^^^

Include files in both headers and implementation files should be ordered as follows:

- C includes such as `stdio.h`
- C++ includes such as `string` and `vector`
- Local include headers from Zeek 

Commenting
^^^^^^^^^^

Functions inside of header files should include doxygen-style comments, including documentation for all parameters and return values. Implementation of those methods in `cc` files do not need to include the comment.

Non-obvious algorithms should include comments about what the code is doing to aid in later maintenance. Avoid writing comments for code where it is obvious what that code is doing.

Spaces and control statements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Spaces should exist inside the outer parentheses for all control statements, but not function calls. A space should also follow the keyword. For example:

::

  if ( condition )
	{
	}
	
  SomeFunction(arg1);

Space after not-operator (`!`)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A space should exist after any not-operator. For example:

::

  if ( ! condition )
	{
	}

Pointer and reference arguments/variables
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Pointer and reference characters should modify the type of the argument, not the variable. For example, `int* var` and not `int *var`;

Visibility ordering
^^^^^^^^^^^^^^^^^^^

Use the ordering `public` -> `protected` -> `private` in class definitions for members. If the class includes `friend` methods, list those at the start of the class.

Language support and preferences
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Zeek build system only supports up to C++11 as supported by gcc 4.8.3 (meaning not the whole C++11 feature set). This is due to compiler support on the target platforms users have reported needing.

Exceptions
**********

Avoid using exceptions for error handling. The primary reason to avoid them is that it makes error handling more difficult to reason about. Due to the nature of the reference counting in the Zeek code, exceptions will often cause the counting to be invalid unless handled very carefully.

Casting
*******

Use C++-style casting (`static_cast`, `dynamic_cast`, `reinterpret_cast`, `const_cast`) instead of bare C-style casts.

Strings
*******

One artifact of the long life of this Zeek code is that a large number of the strings are plain `char*` values. For new code, use std::string instead.

Explicit constructors
*********************

Single-argument constructors should be marked `explicit` to aid in type-checking.

Global namespace
****************

Another artifact of the old Zeek code is that a large amount of variables, functions, and constants are defined in the global namespace and then `extern`'d when needed in other places. Avoid adding any more to the global namespace when possible. Prefer using constructs like the Singleton pattern or static class members instead.

Function parameter passing
**************************

Follow the typical C++ best practices for parameter passing. Never pass objects by value, instead passing them by reference or const reference depending on if they're going to be modified.
