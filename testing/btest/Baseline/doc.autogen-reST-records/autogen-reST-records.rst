.. Automatically generated.  Do not edit.

autogen-reST-records.bro
========================

:download:`Original Source File <autogen-reST-records.bro>`

Overview
--------


Summary
~~~~~~~
Types
#####
============================================ ============================================================
:bro:type:`SimpleRecord`: :bro:type:`record`

:bro:type:`TestRecord`: :bro:type:`record`   Here's the ways records and record fields can be documented.
============================================ ============================================================

Public Interface
----------------
Types
~~~~~
.. bro:type:: SimpleRecord

   :Type: :bro:type:`record`

      field1: :bro:type:`bool`

      field2: :bro:type:`count`

.. bro:type:: TestRecord

   :Type: :bro:type:`record`

      A: :bro:type:`count`
         document ``A``

      B: :bro:type:`bool`
         document ``B``

      C: :bro:type:`SimpleRecord`
         and now ``C``
         is a declared type

      D: :bro:type:`set` [:bro:type:`count`, :bro:type:`bool`]
         sets/tables should show the index types

   Here's the ways records and record fields can be documented.

