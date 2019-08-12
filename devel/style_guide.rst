Zeek Coding Style and Development Guide
=======================================

Historical Context
------------------

The Zeek codebase is quite old as code goes, with the original code being written in 1995. Some of the internal container types date from around 1987. This means that a large portion of it was written before a lot of modern C++ existed. As such, a lot of the early design decisions were made in that context. This guide strives to suggest modern techniques where possible, even when the existing code doesn't follow it to the letter. All new code should follow this guide. Old code should be updated to follow this guide when it is modified. 

Coding conventions and style guide
----------------------------------

Basic Formatting and Indentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The base formatting for all Zeek C++ code, including C++ code inside BIF files, follows the Whitesmiths coding style (https://en.wikipedia.org/wiki/Indentation_style#Whitesmiths_style).

Tabs vs. Spaces
^^^^^^^^^^^^^^^

Use tabs for indentation and spaces for alignment. An example for alignment is below.

.. sourcecode:: c++

  |--\t--|void FunctionWithALongName(int argument1,
  |--\t--|...........................int argument2);

Tabs are used for the second line to line up with the start of the line above it, and then spaces are used to force the alignment with the line above it.

File naming
^^^^^^^^^^^

Header files should always use the `.h` extension. Implementation files should always use the `.cc` extension.

Include guards
^^^^^^^^^^^^^^

All headers should start with a `#pragma once` line to guard against duplicate includes. Avoid using `#ifndef`/`#define` include guards.

Braces
^^^^^^

For multi-line blocks, braces should start on the line after the construct. Single-line blocks can remove the braces. For single-line function definitions the braces can be on the same line as the function definition, with a tab between the close of the function definition and the opening brace.

Multi-line blocks
*****************

.. sourcecode:: c++

  if ( true )
	{
	DoSomething();
	DoSomethingElse();
	}

Single-line functions
*********************

.. sourcecode:: c++

  bool Foo()	{ return false; }

Note that for single-line functions there should be a tab between the closing `)` and the opening `{`.


Function and variable naming
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Type names (classes, enums, structs, etc) and function names should always be `CamelCase`. Variable names, including member variables, should always be `snake_case`. Prefer using more descriptive variable names, except for counter variables.

Including files
^^^^^^^^^^^^^^^

Include files in both headers and implementation files should be ordered as follows:

- C includes such as `stdio.h`
- C++ includes such as `string` and `vector`
- Local include headers from Zeek

Use angle braces around the file name for anything not coming directly from the Zeek code base. This includes any system headers, any external libraries, and anything that can be referring to a file outside the code distribution, even if typically it does refer to a file within the Zeek source tree because it's embedded for convenience (e.g. Broker/CAF). Use quotes around the file name for anything coming from the Zeek code base. This includes "external" libraries like Broker, since they are part of the Zeek code distribution.

Use forward declarations instead of including whenever possible.

Commenting
^^^^^^^^^^

Functions inside of header files should include doxygen-style comments, including documentation for all parameters and return values. Implementation of those methods in `cc` files do not need to include the comment.

Non-obvious algorithms should include comments about what the code is doing to aid in later maintenance. Avoid writing comments for code where it is obvious what that code is doing.

Spaces and control statements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Spaces should exist inside the outer parentheses for all control statements, but not function calls. A space should also follow the keyword. For example:

.. sourcecode:: c++

  if ( condition )
	{
	}
	
  SomeFunction(arg1);

Space after not-operator (`!`)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A space should exist after any not-operator. For example:

.. sourcecode:: c++

  if ( ! condition )
	{
	}

Pointer and reference arguments/variables
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Pointer and reference characters should modify the type of the argument, not the variable. For example, `int* var` and not `int *var`;

Visibility and member ordering
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Use the ordering `public` -> `protected` -> `private` in class definitions for members.
- If the class includes `friend` methods, list those at the start of the class prior to the `public` block.
- Within each visibility block, use the following ordering for members:
    - Static member functions
    - Non-static member functions
    - Static member variables
    - Non-static member variables
- Attempt to order member variables to avoid the compiler adding padding between them and bloating the size of the objects.

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

One artifact of the long life of this Zeek code is that a large number of the strings created internally are plain `char*` values. For new code, prefer using std::string instead.

Explicit constructors
*********************

Single-argument constructors should be marked `explicit` to aid in type-checking.

Global namespace
****************

Another artifact of the old Zeek code is that a large amount of variables, functions, and constants are defined in the global namespace and then `extern`'d when needed in other places. Avoid adding any more to the global namespace when possible. Prefer using constructs like the Singleton pattern or static class members instead.

Function parameter passing
**************************

Follow the typical C++ best practices for parameter passing. Avoid passing large objects by value, except in cases where the function can use move semantics and the caller can use `std::move`. For objects that will not be modified by the function, pass by const-reference. For objects that may be modified by the function, prefer making the argument a pointer instead of a reference.
