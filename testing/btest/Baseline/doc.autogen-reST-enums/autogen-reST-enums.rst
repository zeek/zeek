.. Automatically generated.  Do not edit.

:tocdepth: 3

autogen-reST-enums.bro
======================




:Source File: :download:`autogen-reST-enums.bro`

Summary
~~~~~~~
Types
#####
======================================= ======================================
:bro:type:`TestEnum1`: :bro:type:`enum` There's tons of ways an enum can look.

:bro:type:`TestEnum2`: :bro:type:`enum` The final comma is optional
======================================= ======================================

Redefinitions
#############
======================================= =======================
:bro:type:`TestEnum1`: :bro:type:`enum` redefs should also work

:bro:type:`TestEnum1`: :bro:type:`enum` now with a comma
======================================= =======================

Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: TestEnum1

   :Type: :bro:type:`enum`

      .. bro:enum:: ONE TestEnum1

         like this

      .. bro:enum:: TWO TestEnum1

         or like this

      .. bro:enum:: THREE TestEnum1

         multiple
         comments
         and even
         more comments

   There's tons of ways an enum can look...

.. bro:type:: TestEnum2

   :Type: :bro:type:`enum`

      .. bro:enum:: A TestEnum2

         like this

      .. bro:enum:: B TestEnum2

         or like this

      .. bro:enum:: C TestEnum2

         multiple
         comments
         and even
         more comments

   The final comma is optional

Redefinitions
#############
:bro:type:`TestEnum1`

   :Type: :bro:type:`enum`

      .. bro:enum:: FOUR TestEnum1

         adding another
         value

   redefs should also work

:bro:type:`TestEnum1`

   :Type: :bro:type:`enum`

      .. bro:enum:: FIVE TestEnum1

         adding another
         value

   now with a comma

